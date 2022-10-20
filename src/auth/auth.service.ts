import { BadRequestException, Injectable } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { hash, verify } from 'argon2'
import { PrismaService } from 'src/prisma/prisma.service'
import LoginDto from './dto/login.dto'
import RegisterDto from './dto/register.dto'

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService) {}

  /**
   * 注册
   * @param dto
   * @returns
   */
  async register(dto: RegisterDto) {
    const user = await this.prisma.user.create({
      data: {
        name: dto.name,
        password: await hash(dto.password),
      },
    })
    return this.token(user)
  }

  /**
   * 登录
   * @param dto
   * @returns
   */
  async login(dto: LoginDto) {
    const user = await this.prisma.user.findUnique({
      where: {
        name: dto.name,
      },
    })
    if (!(await verify(user.password, dto.password))) {
      throw new BadRequestException('密码输入错误')
    }
    return this.token(user)
  }

  /**
   * 生成token
   * @param u
   * @returns
   */
  private async token({ name, id }) {
    return {
      token: await this.jwt.signAsync({
        name,
        sub: id,
      }),
    }
  }
}
