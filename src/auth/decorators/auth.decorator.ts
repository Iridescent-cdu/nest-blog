import { applyDecorators, SetMetadata, UseGuards } from '@nestjs/common'
import { AuthGuard } from '@nestjs/passport'
import { Role } from '../enum'
import { RoleGuard } from '../guards/role.guard'

export function Auth(...roles: Role[]) {
  /**
   * SetMetadata()方法保存了形参角色数据
   */
  return applyDecorators(SetMetadata('roles', roles), UseGuards(AuthGuard('jwt'), RoleGuard))
}
