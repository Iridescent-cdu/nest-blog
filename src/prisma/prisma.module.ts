import { Global, Module } from '@nestjs/common'
import { PrismaService } from './prisma.service'

/**
 * 注册为全局模块
 */
@Global()
@Module({
  providers: [PrismaService],
  exports: [PrismaService],
})
export class PrismaModule {}
