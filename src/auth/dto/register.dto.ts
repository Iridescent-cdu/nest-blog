/**
 * 2.使用dto搭配class-validator及管道进行入参验证
 */
import { IsNotEmpty } from 'class-validator'
import { IsConfirm } from 'src/common/rules/is-confirm.rule'
import { IsNotExistsRule } from 'src/common/rules/is-not-exists.rule'

/**
 * 1.使用dto约束类型，并获得类型提示
 */
export default class RegisterDto {
  @IsNotEmpty({ message: '用户名不能为空' })
  @IsNotExistsRule('user', { message: '用户已经注册' })
  name: string
  @IsNotEmpty({ message: '密码不能为空' })
  @IsConfirm('user', { message: '两次密码不一致' })
  password: string
  @IsNotEmpty({ message: '确认密码不能为空' })
  password_confirm: string
}
