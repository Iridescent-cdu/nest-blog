import { ClassSerializerInterceptor } from '@nestjs/common'
import { NestFactory, Reflector } from '@nestjs/core'
import { NestExpressApplication } from '@nestjs/platform-express'
import { AppModule } from './app.module'
import Validate from './common/validate'
import { TransformInterceptor } from './transform.interceptor'

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule)
  /**
   * 使用全局管道
   */
  app.useGlobalPipes(new Validate())
  /**
   * 使用全局拦截器
   */
  app.useGlobalInterceptors(new TransformInterceptor())
  /**
   * 设置全局API前缀
   */
  app.setGlobalPrefix('api')
  /**
   * 设置静态资源访问目录
   */
  app.useStaticAssets('uploads', { prefix: '/uploads' })
  /**
   * 注册序列化响应
   */
  app.useGlobalInterceptors(new ClassSerializerInterceptor(app.get(Reflector)))
  await app.listen(3000)
}
bootstrap()
