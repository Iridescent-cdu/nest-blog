import { Controller, Post, Body } from '@nestjs/common'
import { AuthService } from './auth.service'
import LoginDto from './dto/login.dto'
import RegisterDto from './dto/register.dto'

@Controller()
export class AuthController {
  constructor(private auth: AuthService) {}
  @Post('register')
  register(@Body() body: RegisterDto) {
    return this.auth.register(body)
  }

  @Post('login')
  login(@Body() body: LoginDto) {
    return this.auth.login(body)
  }
}
