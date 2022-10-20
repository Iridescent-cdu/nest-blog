import { ExtractJwt, Strategy } from 'passport-jwt'
import { PassportStrategy } from '@nestjs/passport'
import { Injectable } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { PrismaService } from '@/prisma/prisma.service'

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(configService: ConfigService, private prisma: PrismaService) {
    super({
      //解析用户提交的header：Bearer Token 数据
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      //加密码的secret or key
      secretOrKey: configService.get('TOKEN_SECRET'),
    })
  }
  //验证通过后获取用户资料,用户资料将会被放进context.switchToHttp().getRequest()中
  async validate({ sub: id }) {
    return this.prisma.user.findUnique({
      where: {
        id,
      },
    })
  }
}
