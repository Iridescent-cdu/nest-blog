import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common'
import { Reflector } from '@nestjs/core'
import { user } from '@prisma/client'
import { Observable } from 'rxjs'
import { Role } from '../enum'

@Injectable()
export class RoleGuard implements CanActivate {
  constructor(private reflector: Reflector) {}
  canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
    //获取身份认证策略传入的user身份信息
    const user = context.switchToHttp().getRequest().user as user
    //通过反射获取上下文传入的元数据信息以获取守卫传入的权限控制参数
    const roles = this.reflector.getAllAndMerge<Role[]>('roles', [context.getHandler(), context.getClass()])
    /**
     * 1.获取此次登录的用户信息
     * 2.获取装饰器守卫传入的权限控制角色参数：@Auth(Role.ADMIN)
     * 3.批量判断登录的用户信息的权限是否在传入的参数中
     * 4.通过roles.length来判断没传角色参数时返回为true
     */
    return roles.length ? roles.some((role) => user.role === role) : true
  }
}
