import { Module } from '@nestjs/common'
import { AuthService } from './auth.service'
import { AuthController } from './auth.controller'
import { JwtModule } from '@nestjs/jwt'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { JwtStrategy } from './strategy/jwt.strategy'

@Module({
  /**
   * 在导入的时候进行注册
   */
  imports: [
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => {
        return {
          secret: config.get('TOKEN_SECRET'),
          signOptions: {
            expiresIn: '100d',
          },
        }
      },
    }),
  ],
  //注册JwtStrategy身份验证策略
  providers: [AuthService, JwtStrategy],
  controllers: [AuthController],
})
export class AuthModule {}
