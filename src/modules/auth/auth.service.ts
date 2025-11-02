import {
  BadRequestException,
  ConflictException,
  Inject,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import Redis from 'ioredis';
import { RegisterDTO } from './dto/register.dto';
import * as bcrypt from 'bcrypt';
import { LoginDTO } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { Response } from 'express';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/modules/auth/entity/user.entity';
import { Repository } from 'typeorm';
import { PayloadRFToken, ResponseUser } from './interface/login.interface';
import { TodoService } from 'src/modules/todo/todo.service';
import { RedisPubSubAuth } from 'src/common/constant/redis-pubsub.constant';
import { TypeOtp } from './enum/otp.type';
import { AuthQueue } from './bullmq/auth/auth.queue';

@Injectable()
export class AuthService {
  private key = 'users';
  constructor(
    @Inject('REDIS_CLIENT') private readonly redis: Redis,
    @Inject('REDIS_PUB') private readonly redisPub: Redis,
    private readonly jwtService: JwtService,
    private readonly authQueue: AuthQueue,
    private readonly todoService: TodoService,
    @InjectRepository(User) private userRepository: Repository<User>,
  ) {}

  async register(dto: RegisterDTO) {
    const { emailTrim, passwordTrim } = this.trimUser(dto.email, dto.password);
    const userRepo = await this.userRepository.findOneBy({ email: emailTrim });
    if (userRepo)
      throw new ConflictException({
        message: 'Email is already',
        error: 'email_conflict',
      });
    const hassPass = await bcrypt.hash(passwordTrim, 10);

    const user = {
      name: dto.name,
      email: emailTrim,
      password: hassPass,
      isVerify: false,
    };
    const newUser = this.userRepository.create(user);
    const createUser = await this.userRepository.save(newUser);
    const { password: _, isVerify: __, isBlock: ___, ...safeUser } = createUser;
    return safeUser;
  }

  async login(dto: LoginDTO, res: Response) {
    const { email, password } = dto;
    const { emailTrim, passwordTrim } = this.trimUser(email, password);
    const userDB = await this.userRepository.findOneBy({ email: emailTrim });
    if (!userDB) throw new NotFoundException('Email is not correct');

    if (userDB && userDB.isBlock) {
      throw new UnauthorizedException('User is block by Admin!');
    }
    if (userDB && userDB.isVerify === false)
      throw new BadRequestException({
        message: 'Email is not verify',
        error: 'not_verify',
      });
    const isMatch = await bcrypt.compare(passwordTrim, userDB.password);
    if (!isMatch) throw new NotFoundException('Password not correct!');
    const payload = {
      userId: userDB.userId,
      email: userDB.email,
      name: userDB.name,
    };

    const accessToken = this.generateAccessToken(payload);
    await Promise.all([
      this.generateRefreshToken(payload, res),
      this.authQueue.sendWelcome(email),
    ]);
    const { password: _, isVerify: __, isBlock: ___, ...safeUser } = userDB;
    return {
      message: 'Login success',
      accessToken,
      data: safeUser as ResponseUser,
    };
  }

  generateAccessToken(payload: {
    email: string;
    userId: string;
    name: string;
  }): string {
    const accessToken = this.jwtService.sign(
      {
        email: payload.email,
        userId: payload.userId,
        name: payload.name,
      },
      { secret: process.env.JWT_ACCESS_TOKEN },
    );
    return accessToken;
  }

  async generateRefreshToken(
    payload: { email: string; userId: string; name?: string },
    res: Response,
  ) {
    const refresToken = this.jwtService.sign(
      { userId: payload.userId, email: payload.email },
      { secret: process.env.JWT_REFRESH_TOKEN, expiresIn: '7d' },
    );
    res.cookie('refreshToken', refresToken, {
      httpOnly: true,
      sameSite: 'strict',
      path: 'auth/refreshToken',
      maxAge: 1000 * 60 * 60 * 24 * 7,
    });
    await this.redis.set(
      `refresh_token:${payload.userId}`,
      refresToken,
      'EX',
      60 * 60 * 24 * 7,
    );
  }

  async refreshToken(refreshToken: string) {
    let payload: PayloadRFToken;
    try {
      payload = this.jwtService.verify(refreshToken, {
        secret: process.env.JWT_REFRESH_TOKEN,
      });
    } catch (_error) {
      throw new UnauthorizedException('Invalid refreshtoken');
    }
    const userToken = await this.redis.get(`refresh_token:${payload.userId}`);
    if (!userToken)
      throw new UnauthorizedException('Token is expires. Please login again!');
    const user = await this.userRepository.findOneBy({
      userId: payload.userId,
    });
    if (!user) {
      throw new NotFoundException('User is not found');
    }
    const newPayload = {
      userId: user.userId,
      email: user.email,
      name: user.name,
    };
    const accessToken = this.generateAccessToken(newPayload);
    const { password: _, isVerify: __, isBlock: ___, ...safeUser } = user;
    return {
      message: 'Login success',
      accessToken: accessToken,
      data: safeUser,
    };
  }

  async logout(accessToken: string) {
    try {
      const payload: PayloadRFToken = await this.jwtService.verify(
        accessToken,
        {
          secret: process.env.JWT_ACCESS_TOKEN,
        },
      );
      const key = `${this.key}:isBlocked:${accessToken}`;
      const now = Math.floor(Date.now() / 1000);
      const ttl = Math.max(0, payload.exp - now);
      await this.redis.set(key, accessToken.toString(), 'EX', ttl);
    } catch (error) {
      throw new UnauthorizedException('Invalid token', error as string);
    }
    return {
      message: `Logout successfull`,
    };
  }

  async deleteAccout(userId: string) {
    const userExist = await this.userRepository.findOneBy({ userId });
    if (!userExist) throw new NotFoundException('Accout not found!');
    await this.todoService.deleteTods(userId);
    await this.userRepository.remove(userExist);

    return {
      message: `Delete accout success`,
    };
  }

  async sendOtp(email: string, type: TypeOtp) {
    const emailExist = await this.userRepository.findOneBy({ email });
    if (!emailExist)
      throw new NotFoundException({
        message: 'Email not found',
        error: 'not_found',
      });
    const key = `otps:${type}:${email}`;
    const redisCheck = await this.redis.get(key);
    if (redisCheck) {
      await this.redis.del(key);
    }
    await this.redisPub.publish(
      RedisPubSubAuth.SendOTP,
      JSON.stringify({ email, type }),
    );
  }

  async verifyOtp(
    email: string,
    otp: string,
    type: TypeOtp,
    oldPassword?: string,
    newPassword?: string,
  ) {
    const user = await this.userRepository.findOneBy({
      email,
    });
    if (!user)
      throw new NotFoundException({
        message: 'User not found',
        error: 'not_found',
      });
    const key = `otps:${type}:${email}`;
    const verify = await this.redis.get(key);
    const otpParse = JSON.parse(verify as string) as string;
    if (otpParse === otp) {
      if (type === TypeOtp.Register) {
        await this.redis.del(key);
        return this.registerVeri(user);
      } else if (type === TypeOtp.ResetPassword) {
        await this.redis.del(key);
        return this.resetVeri(
          user,
          oldPassword as string,
          newPassword as string,
        );
      } else if (type === TypeOtp.forgotPassword) {
        await this.redis.del(key);

        return this.forgotVeri(user, newPassword as string);
      }
    }
    throw new BadRequestException({
      message: 'OTP is not correct',
      error: 'otp_invalid',
    });
  }

  private trimUser(email: string, password: string) {
    const emailTrim = email.trim();
    const passwordTrim = password.trim();
    return {
      emailTrim,
      passwordTrim,
    };
  }

  async registerVeri(user: User) {
    user.isVerify = true;
    await this.userRepository.save(user);
    if (!user)
      throw new BadRequestException({
        message: 'Verify fail. Please check email',
        error: 'verify_fail',
      });
    return { message: 'Verify is successfull' };
  }

  async resetVeri(user: User, oldPassword: string, newPassword: string) {
    const trimOldPass = oldPassword.trim();
    const trimNewPass = newPassword.trim();
    const isMatch = await bcrypt.compare(trimOldPass, user.password);
    if (!isMatch)
      throw new BadRequestException({
        message: 'Old password is not correct',
        error: 'old_pass_not_correct',
      });
    const hassPassword = await bcrypt.hash(trimNewPass, 10);
    user.password = hassPassword;
    await this.userRepository.save(user);
    return { message: 'Reset password is successfull' };
  }

  async forgotVeri(user: User, newPassword: string) {
    const hassPassword = await bcrypt.hash(newPassword, 10);
    user.password = hassPassword;
    const updated = await this.userRepository.save(user);
    if (!updated) throw new Error('Update fail');
    return { message: 'Update password is sucessfull' };
  }
}
