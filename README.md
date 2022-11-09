# 基于Nest.js和Prisma的nest-blog博客

## 1.初始化nest项目

### 1.安装依赖创建数据模型

1. 执行`nest new nest-blog`并使用`pnpm`作为包管理工具

2. 安装依赖

   ```shell
   pnpm add prisma-binding @prisma/client mockjs @nestjs/config class-validator class-transformer argon2 @nestjs/passport passport passport-local @nestjs/jwt passport-jwt lodash multer dayjs express redis @nestjs/throttler
   
   pnpm add -D prisma typescript @types/node @types/mockjs @nestjs/mapped-types @types/passport-local @types/passport-jwt @types/express @types/lodash @types/multer @types/node
   ```

3. 初始化prisma：`npx prisma init`并在`.env`文件修改数据库基本信息

   ```.env
   DATABASE_URL="mysql://root:admin@localhost:3306/nest-blog"
   ```

4. 修改`.prettierrc`文件约束代码格式：

   ```json
   {
     "arrowParens": "always",
     "bracketSameLine": true,
     "bracketSpacing": true,
     "embeddedLanguageFormatting": "auto",
     "htmlWhitespaceSensitivity": "css",
     "insertPragma": false,
     "jsxSingleQuote": false,
     "printWidth": 120,
     "proseWrap": "never",
     "quoteProps": "as-needed",
     "requirePragma": false,
     "semi": false,
     "singleQuote": true,
     "tabWidth": 2,
     "trailingComma": "all",
     "useTabs": false,
     "vueIndentScriptAndStyle": false,
     "singleAttributePerLine": false
   }
   ```

5. 创建`user`和`article`数据模型并执行`npx prisma migrate dev`生成迁移文件并创建表：**值得注意的是，生成的数据模型会自动生成TypeScript类型供我们使用**

   ```prisma
   generator client {
     provider = "prisma-client-js"
   }
   
   datasource db {
     provider = "mysql"
     url      = env("DATABASE_URL")
   }
   
   model user {
     id       Int    @id @default(autoincrement()) @db.UnsignedInt
     name     String
     password String
   }
   
   model article {
     id      Int    @id @default(autoincrement()) @db.UnsignedInt
     title   String
     content String @db.Text
   }
   ```

6. 使用`prisma`客户端进行数据填充：

   1. 配置执行环境：

      ```json
        "prisma": {
          "seed": "ts-node prisma/seed.ts"
        },
      ```

   2. 使用`mockjs`模拟数据、`argon2`加密密码

   ```typescript
   import { PrismaClient } from '@prisma/client'
   import { hash } from 'argon2'
   import { Random } from 'mockjs'
   
   const prisma = new PrismaClient()
   
   async function fun() {
     /**
      * prisma在创建数据，以及使用argon2对密码进行加密时都是异步任务需要同步等待
      */
     await prisma.user.create({
       data: {
         name: 'admin',
         password: await hash('admin123'),
       },
     })
   
     for (let i = 0; i < 50; i++) {
       await prisma.article.create({
         data: {
           title: Random.ctitle(10, 30),
           content: Random.cparagraph(30, 50),
         },
       })
     }
   }
   
   ```

   3. 执行`npx prisma migrate reset`执行迁移文件并填充数据（覆写）

### 2.配置路径别名

通过`tsconfig.json`设置路径别名

```json
"paths": {
      "@/*": ["src/*"]
    }
```


## 2.登录模块

### 1.创建auth注册登录模块

```shell
nest g mo auth  
nest g s auth --no-spec 
nest g co auth --no-spec
```

### 2.使用DTO、class-validator、PIPE验证入参

1. 使用dto使我们清晰的了解数据传输对象的结构（获得类型提示）并且约束对象；搭配`class-validator`和PIPE进行入参验证

   ```typescript
   /**
    * 2.使用dto搭配class-validator及管道进行入参验证
    */
   import { IsNotEmpty } from 'class-validator'
   
   /**
    * 1.使用dto约束类型，并获得类型提示
    */
   export default class RegisterDto {
     @IsNotEmpty({ message: '用户名不能为空' })
     name: string
     @IsNotEmpty({ message: '密码不能为空' })
     password: string
   }
   ```

2. **继承内置管道**：在`src/common`下创建`validate.ts`来继承内置管道，可以通过重写其中的方法加强内置管道

   ```javascript
   import { ValidationPipe } from '@nestjs/common'
   
   /**
    *重写内置管道：通过继承内置管道ValidationPipe来实现一个功能更强大的管道
    */
   export default class Validate extends ValidationPipe {}
   ```

3. 全局注册`Validate`管道

   ```javascript
     app.useGlobalPipes(new Validate())
   ```

4. **自定义校验规则**：自定义一个`class-validator`校验规则装饰器

   ```typescript
   import { PrismaClient } from '@prisma/client'
   
   import { registerDecorator, ValidationArguments, ValidationOptions } from 'class-validator'
   
   export function IsNotExistsRule(table: string, ValidationOptions?: ValidationOptions) {
     return function (object: Record<string, any>, propertyName: string) {
       registerDecorator({
         name: 'IsNotExistsRule',
         target: object.constructor,
         propertyName: propertyName,
         constraints: [table],
         options: ValidationOptions,
         validator: {
           async validate(value: string, args: ValidationArguments) {
             const prisma = new PrismaClient()
             const res = await prisma[table].findFirst({
               where: {
                 [args.property]: value,
               },
             })
             return !Boolean(res)
           },
         },
       })
     }
   }
   ```


5. **处理验证错误信息**：重写内置管道的`flattenValidationErrors`方法，获取`class-validator`验证错误的信息并抛出HTTP异常给前端

   ```typescript
   import { HttpException, HttpStatus, ValidationError, ValidationPipe } from '@nestjs/common'
   
   /**
    *重写内置管道：通过继承内置管道ValidationPipe来实现一个功能更强大的管道
    */
   export default class Validate extends ValidationPipe {
     protected flattenValidationErrors(validationErrors: ValidationError[]): string[] {
       const messages = {}
       validationErrors.forEach((error) => {
         messages[error.property] = Object.values(error.constraints)[0]
       })
       throw new HttpException(
         {
           code: 422,
           messages,
         },
         HttpStatus.UNPROCESSABLE_ENTITY,
       )
     }
   }
   ```

6. 增加`password_confirm`字段，并对`password`和`password_confirm`进行校验，添加自定义验证装饰器`IsConfirm`

   ```typescript
   import { registerDecorator, ValidationOptions, ValidationArguments } from 'class-validator'
   
   export function IsConfirm(property: string, validationOptions?: ValidationOptions) {
     return function (object: Record<string, any>, propertyName: string) {
       registerDecorator({
         name: 'IsConfirm',
         target: object.constructor,
         propertyName: propertyName,
         constraints: [property],
         options: validationOptions,
         validator: {
           async validate(value: any, args: ValidationArguments) {
             return Boolean(value == args.object[`${args.property}_confirm`])
           },
         },
       })
     }
   }
   
   ```

### 3.完成注册服务

1. 创建`prisma`模块和服务

   ```shell
    nest g mo prisma 
    nest g s prisma --no-spec
   ```

2. 继承`PrismaClient`客户端并**开启日志打印**

   ```typescript
   import { Injectable } from '@nestjs/common'
   import { PrismaClient } from '@prisma/client'
   
   @Injectable()
   export class PrismaService extends PrismaClient {
     constructor() {
       super({
         log: ['query'],
       })
     }
   }
   ```

3. 将`prisma`注册为全局模块并导出`PrismaService`服务：**值得注意的是，`@Global()`装饰器只是使模块全局可见，也就是其他模块不需要导入，但是我们如果需要使用其中的服务时，需要将对应的服务导出**

   `providers`区别于`exports`：**`providers`注册服务，以便于它可以执行依赖注入**

   ```typescript
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
   
   ```

4. 实现注册服务

   ```typescript
   import { Injectable } from '@nestjs/common'
   import { hash } from 'argon2'
   import { PrismaService } from 'src/prisma/prisma.service'
   import RegisterDto from './dto/register.dto'
   
   @Injectable()
   export class AuthService {
     constructor(private prisma: PrismaService) {}
     async register(dto: RegisterDto) {
       const user = await this.prisma.user.create({
         data: {
           name: dto.name,
           password: await hash(dto.password),
         },
       })
       return user
     }
   }
   
   ```

5. 调用注册服务

   ```typescript
   import { Controller, Post, Body } from '@nestjs/common'
   import { AuthService } from './auth.service'
   import RegisterDto from './dto/register.dto'
   
   @Controller()
   export class AuthController {
     constructor(private auth: AuthService) {}
     @Post('register')
     register(@Body() body: RegisterDto) {
       return this.auth.register(body)
     }
   
     @Post('login')
     login() {
       return 'a'
     }
   }
   
   ```

### 4.用户登录服务

1. 创建`login.dto.ts`进行类型约束和入参验证

   ```typescript
   import { IsNotEmpty } from 'class-validator'
   import { IsExistsRule } from 'src/common/rules/is-exists.rule'
   
   export default class LoginDto {
     @IsNotEmpty({ message: '用户名不能为空' })
     @IsExistsRule('user', { message: '用户不存在' })
     name: string
     @IsNotEmpty({ message: '密码不能为空' })
     password: string
   }
   
   ```

2. 自定义验证装饰器`is-exists.rule.ts`

   ```typescript
   import { PrismaClient } from '@prisma/client'
   
   import { registerDecorator, ValidationArguments, ValidationOptions } from 'class-validator'
   
   export function IsExistsRule(table: string, ValidationOptions?: ValidationOptions) {
     return function (object: Record<string, any>, propertyName: string) {
       registerDecorator({
         name: 'IsNotExistsRule',
         target: object.constructor,
         propertyName: propertyName,
         constraints: [table],
         options: ValidationOptions,
         validator: {
           async validate(value: string, args: ValidationArguments) {
             const prisma = new PrismaClient()
             const res = await prisma[table].findFirst({
               where: {
                 [args.property]: value,
               },
             })
             return Boolean(res)
           },
         },
       })
     }
   }
   ```

3. 实现登录服务：**注意当修改`prisma`之后都需要重新执行prisma生成迁移文件；`npx prisma migrate reset dev`是重新执行已经生成的所有迁移文件**

   ```javascript
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
   ```

### 5.生成token令牌

1. 安装`jwt`依赖包

   ```shell
   pnpm add @nestjs/passport passport passport-local @nestjs/jwt passport-jwt
   pnpm add -D @types/passport-local @types/passport-jwt
   ```

2. 在`.env`文件中创建`jwt`秘钥`TOKEN_SECRET`

   ```.env
   #TOKEN秘钥
   TOKEN_SECRET="houdunren"
   ```

3. 使用`@nestjs/config `提供的`ConfigModule`来处理配置项；将`ConfigModule`动态模块注册为全局

   ```typescript
   @Module({
     imports: [
       AuthModule,
       PrismaModule,
       ConfigModule.forRoot({
         isGlobal: true,
       }),
     ],
   })
   export class AppModule {}
   ```

4. 导入`JwtModule`模块并进行`token`配置：秘钥、过期时间

   ```typescript
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
     providers: [AuthService],
     controllers: [AuthController],
   })
   export class AuthModule {}
   ```

5. 使用`jwt.signAsync`生成token

   ```typescript
    /**
      * 生成token
      * @param u
      * @returns
      */
     private async token({ id, name }) {
       return {
         token: await this.jwt.signAsync({
           name,
           sub: id,
         }),
       }
     }
   ```

## 3.文章模块

### 1.创建文章模块

使用`nest g res article  --no-spec `创建一个完整的模块并选用`REST API`

### 2.获取文章列表与分页数据

1. 使用环境变量保存每次返回的数据条数，即每页文章数

   ```.env
   #每页文章数
   ARTICLE_PAGE_ROW=10
   ```

2. 根据页码和每页文章数获取文章并返回元数据

   ```typescript
    async findAll(page = 1) {
       /**
        * 分页器：每次取10条
        */
       const row = this.config.get('ARTICLE_PAGE_ROW')
       const articles = await this.prisma.article.findMany({
         skip: (page - 1) * row,
         take: +row,
       })
       const total = await this.prisma.article.count()
       /**
        * 返回元数据：数据都将放在http响应中的data节点里
        */
       return {
         meta: {
           currenet_page: page,
           page_row: row,
           total,
           total_page: Math.ceil(total / row),
         },
         data: articles,
       }
     }
   ```

3. 使用拦截器将元数据抽离出`data`节点，并全局注册拦截器

   ```typescript
   import { CallHandler, ExecutionContext } from '@nestjs/common'
   import { NestInterceptor } from '@nestjs/common'
   import { Injectable } from '@nestjs/common'
   import { map } from 'rxjs/operators'
   
   @Injectable()
   export class TransformInterceptor implements NestInterceptor {
     intercept(context: ExecutionContext, next: CallHandler) {
       return next.handle().pipe(
         map((data) => {
           return data?.meta ? data : { data }
         }),
       )
     }
   }
   
   
   
     /**
      * 使用全局拦截器
      */
    app.useGlobalInterceptors(new TransformInterceptor())
   ```

### 3.获取单条文章和文章添加删除修改

1. 获取单条文章

   ```typescript
     findOne(id: number) {
       return this.prisma.article.findFirst({
         where: {
           id,
         },
       })
     }
   ```

2. 文章添加

   1. `create-article.dto.ts`中约束文章参数并添加类型

      ```typescript
      import { IsNotEmpty } from 'class-validator'
      
      export class CreateArticleDto {
        @IsNotEmpty({ message: '标题不能为空' })
        title: string
        @IsNotEmpty({ message: '内容不能为空' })
        content: string
      }
      ```

   2. 在`article.service.ts`中进行文章添加

      ```typescript
       create(createArticleDto: CreateArticleDto) {
          return this.prisma.article.create({
            data: {
              title: createArticleDto.title,
              content: createArticleDto.content,
            },
          })
        }
      ```

3. 文章删除：在`article.service.ts`中进行文章删除

   ```typescript
    remove(id: number) {
       return this.prisma.article.delete({
         where: {
           id,
         },
       })
     }
   ```

4. 文章修改：在`article.service.ts`中进行文章修改

   ```typescript
     update(id: number, updateArticleDto: UpdateArticleDto) {
       return this.prisma.article.update({
         where: {
           id,
         },
         data: updateArticleDto,
       })
     }
   ```

5. 在`apifox`中定义公共自动化脚本后置操作获取环境变量并保存

   ```javascript
   pm.sendRequest("http://localhost:3000/article", function (err, response) {
       const articles = response.json()
       pm.environment.set("article_id", articles.data[0].id);
   
   });
   ```

### 4.设置api请求前缀

1. 使用express作为底层框架

   ```typescript
    const app = await NestFactory.create<NestExpressApplication>(AppModule)
   ```

2. 设置全局接口前缀

   ```typescript
    /**
      * 设置全局API前缀
      */
     app.setGlobalPrefix('api')
   ```

## 4.栏目模块

### 1.创建栏目模块数据模型

1. 创建数据模型，删除原来的`article`数据，重新执行迁移文件生成表：**由于添加了外键约束，而之前的数据缺少，导致重新生成迁移文件时报错**

   ```prisma
   model category {
     id       Int       @id @default(autoincrement()) @db.UnsignedInt
     title    String
     articles article[]
   }
   
   model article {
     id         Int      @id @default(autoincrement()) @db.UnsignedInt
     title      String
     content    String   @db.Text
     category   category @relation(fields: [categoryId], references: [id])
     categoryId Int      @db.UnsignedInt
   }
   ```

2. 执行数据填充：`npx prisma migrate reset`，因为使用了默认导入，需要在`tsconfig.json`开启` "esModuleInterop": true`

   ```typescript
     /**
      * 生成栏目
      */
     for (let i = 1; i <= 5; i++) {
       await prisma.category.create({
         data: {
           title: Random.ctitle(3, 6),
         },
       })
     }
   
     /**
      * 创建文章
      */
     for (let i = 0; i < 50; i++) {
       await prisma.article.create({
         data: {
           title: Random.ctitle(10, 30),
           content: Random.cparagraph(30, 50),
           categoryId: _.random(1, 5),
         },
       })
     }
   ```

### 2.创建栏目模块

1. 创建栏目模块：`nest g res category --no-spec`

2. 使用`dto`约束类型：

   ```typescript
   import { IsNotEmpty } from 'class-validator'
   
   export class CreateCategoryDto {
     @IsNotEmpty({ message: '栏目标题不能为空' })
     title: string
   }
   ```

3. 编写`category`增删改查接口：**注意删除接口无法成功，因为category被article表所参照**

   ```typescript
   import { PrismaService } from '@/prisma/prisma.service'
   import { Injectable } from '@nestjs/common'
   import { CreateCategoryDto } from './dto/create-category.dto'
   import { UpdateCategoryDto } from './dto/update-category.dto'
   
   @Injectable()
   export class CategoryService {
     constructor(private prisma: PrismaService) {}
     create(createCategoryDto: CreateCategoryDto) {
       return this.prisma.category.create({
         data: createCategoryDto,
       })
     }
   
     findAll() {
       return this.prisma.category.findMany()
     }
   
     findOne(id: number) {
       return this.prisma.category.findFirst({
         where: {
           id: id,
         },
       })
     }
   
     update(id: number, updateCategoryDto: UpdateCategoryDto) {
       return this.prisma.category.update({
         where: {
           id,
         },
         data: updateCategoryDto,
       })
     }
   
     remove(id: number) {
       return this.prisma.category.delete({
         where: {
           id,
         },
       })
     }
   }
   ```

### 3.修复文章接口

1. 在`create-article.dto.ts`中新增`categoryId`字段

   ```typescript
   import { IsNotEmpty } from 'class-validator'
   
   export class CreateArticleDto {
     @IsNotEmpty({ message: '标题不能为空' })
     title: string
     @IsNotEmpty({ message: '内容不能为空' })
     content: string
     @IsNotEmpty({ message: '栏目不能为空' })
     categoryId: string
   }
   
   ```

2. 修复新增接口：增加新的必填参数`categoryId`

   ```typescript
     create(createArticleDto: CreateArticleDto) {
       return this.prisma.article.create({
         data: {
           title: createArticleDto.title,
           content: createArticleDto.content,
           categoryId: +createArticleDto.categoryId,
         },
       })
     }
   ```

3. 修复更新接口：**需要将传递的参数`categoryId`转为数据库需要的`number`类型**

   ```typescript
    update(id: number, updateArticleDto: UpdateArticleDto) {
       return this.prisma.article.update({
         where: {
           id,
         },
         /**
          * 传过来的id默认为字符串，而数据库中的id需要number类型，这里进行了转换
          */
         data: { ...updateArticleDto, categoryId: +updateArticleDto.categoryId },
       })
     }
   ```

## 5.身份认证

### 1.编写身份认证策略

1. 在`src/auth/`目录下创建`strategy/jwt.strategy.ts`

   ```typescript
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
   
   ```

2. 在`auth.module.ts`中注册`JwtStrategy`

   ```typescript
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
   ```

3. 导入并使用守卫进行验证

   ```typescript
   import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards } from '@nestjs/common'
   import { AuthGuard } from '@nestjs/passport'
   import { CategoryService } from './category.service'
   import { CreateCategoryDto } from './dto/create-category.dto'
   import { UpdateCategoryDto } from './dto/update-category.dto'
   
   @Controller('category')
   export class CategoryController {
     constructor(private readonly categoryService: CategoryService) {}
   
     @Post()
     @UseGuards(AuthGuard('jwt'))
     create(@Body() createCategoryDto: CreateCategoryDto) {
       return this.categoryService.create(createCategoryDto)
     }
   ```


### 2.用户表添加角色类型

1. 在`prisma\schema.prisma`文件中为`user`先建`role`字段

   ```prisma
   model user {
     id       Int     @id @default(autoincrement()) @db.UnsignedInt
     name     String  @unique
     password String
     role     String?
   }
   ```

2. 重新执行`npx prisma migrate dev`生成迁移文件

3. 在`prisma\seed.ts`填充数据

   ```typescript
     await prisma.user.create({
       data: {
         name: 'admin',
         password: await hash('admin123'),
         role: 'admin',
       },
     })
   ```

### 3.组合装饰器

1. Nest 提供了一个辅助方法`applyDecorators`来组合多个装饰器：在`src\auth\decorators\auth.decorator.ts`中组合 `@UseGuards(AuthGuard('jwt'))`

   ```typescript
   import { applyDecorators, SetMetadata, UseGuards } from '@nestjs/common'
   import { AuthGuard } from '@nestjs/passport'
   import { Role } from '../enum'
   
   export function Auth(...roles: Role[]) {
     return applyDecorators(SetMetadata('roles', roles), UseGuards(AuthGuard('jwt')))
   }
   ```

2. 处理`Auth()`的参数，定义`src\auth\enum.ts`枚举

   ```typescript
   export enum Role {
     ADMIN = 'admin',
   }
   ```

### 4.定义角色守卫

1. 执行`nest g gu auth/guards/role --no-spec`创建角色守卫

2. 对登录的角色进行权限控制：

   1. 获取身份认证策略传入的user身份信息：` const user = *context*.switchToHttp().getRequest().user as *user*`
   2. 通过反射获取上下文传入的元数据信息以获取守卫传入的权限控制参数：` const roles = *this*.reflector.getAllAndMerge<*Role*[]>('roles', [*context*.getHandler(), *context*.getClass()])`
   3. 将身份信息与权限控制参数做批量判断处理

   ```typescript
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
   
   ```

## 6.文件上传

1. 创建文件上传模块

   ```shell
   nest g mo upload 
   nest g s upload --no-spec
   nest g co upload --no-spec
   ```

2. 导入被注册内置模块`MulterModule`

   ```typescript
   import { Module } from '@nestjs/common'
   import { MulterModule } from '@nestjs/platform-express'
   import { diskStorage } from 'multer'
   import { extname } from 'path'
   import { UploadService } from './upload.service'
   
   @Module({
     //导入并注册MulterModule内置模块
     imports: [
       MulterModule.registerAsync({
         useFactory() {
           return {
             storage: diskStorage({
               destination: 'uploads',
               filename: (req, file, callback) => {
                 const path = Date.now() + '-' + Math.round(Math.random() * 1e10) + extname(file.originalname)
                 callback(null, path)
               },
             }),
           }
         },
       }),
     ],
     providers: [UploadService],
   })
   export class UploadModule {}
   
   ```

3. 上传处理和装饰器组合

   ```typescript
   import { applyDecorators, UnsupportedMediaTypeException, UseInterceptors } from '@nestjs/common'
   import { FileInterceptor } from '@nestjs/platform-express'
   import { MulterOptions } from '@nestjs/platform-express/multer/interfaces/multer-options.interface'
   
   //上传类型验证
   export function filterFilter(type: string) {
     return (req: any, file: Express.Multer.File, callback: (error: Error | null, acceptFile: boolean) => void) => {
       if (!file.mimetype.includes(type)) {
         callback(new UnsupportedMediaTypeException('文件类型错误'), false)
       } else {
         callback(null, true)
       }
     }
   }
   
   //文件上传
   export function Upload(field = 'file', options: MulterOptions) {
     return applyDecorators(UseInterceptors(FileInterceptor(field, options)))
   }
   
   //图片上传
   export function Image(field = 'file') {
     return Upload(field, {
       //上传文件大小限制
       limits: Math.pow(1024, 2) * 2,
       fileFilter: filterFilter('image'),
     } as MulterOptions)
   }
   
   //文档上传
   export function Document(field = 'file') {
     return Upload(field, {
       //上传文件大小限制
       limits: Math.pow(1024, 2) * 5,
       fileFilter: filterFilter('document'),
     } as MulterOptions)
   }
   ```

4. 添加图片上传接口

   ```typescript
   import { Controller, Post, UploadedFile } from '@nestjs/common'
   import { Image } from './upload'
   
   @Controller('upload')
   export class UploadController {
     @Post('image')
     @Image()
     image(@UploadedFile() file: Express.Multer.File) {
       return file
     }
   }
   ```

5. 设置静态资源访问目录

   ```typescript
   import { NestFactory } from '@nestjs/core'
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
     await app.listen(3000)
   }
   bootstrap()
   ```

## 7.完成前端页面

### 1.栏目处理

1. 在`types\model.d.ts`使用`JSON to TS`将json格式数据自动转换为类型声明

   ```typescript
   interface CategoryModel {
     id: number
     title: string
   }
   ```

2. 遇到的问题：**模块“"@prisma/client"”没有导出的成员“PrismaClient”。ts(2305)**；解决方案：重新生成prisma客户端`npx prisma generate`

3. 在`src\apis\category.ts`定义api接口

   ```typescript
   import { http } from '@/plugins/axios'
   
   export function getAllCategory() {
     return http.request<CategoryModel[]>({
       url: 'category',
     })
   }
   ```

4. 抽离逻辑， 在`src\composables\useCategory.ts`定义获取数据的逻辑

   ```typescript
   import { getAllCategory } from '@/apis/category'
   import { ref } from 'vue'
   
   export default () => {
     const categories = ref<CategoryModel[]>()
     const all = async () => {
       categories.value = await getAllCategory()
     }
     return { all, categories }
   }
   
   ```

5. 调用获取数据：注意`all()`同样需要使用`await`等待

   ```vue
   <script setup lang="ts">
   import useCategory from '@/composables/useCategory'
   
   const { all, categories } = useCategory()
   await all()
   </script>
   ```

### 2.文章处理

1. 获取文章数据模型和分页信息转换为ts类型声明

   ```typescript
   interface ArticleModel {
     id: number
     title: string
     content: string
     categoryId: number
   }
   
   //分页请求响应结构
   interface ApiPage<T> {
     data: T[]
     meta: {
       currenet_page: number
       page_row: string
       total: number
       total_page: number
     }
   }
   ```

2. 在`src\apis\article.ts`创建article接口

   ```typescript
   import { http } from '@/plugins/axios'
   
   export function getArticleList() {
     return http.request<ApiPage<ArticleModel>>({
       url: 'article',
     })
   }
   ```

3. 封装`src\composables\useArticle.ts`请求

   ```typescript
   import { getArticleList } from '@/apis/article'
   import { ref } from 'vue'
   
   export default () => {
     const pageResult = ref<CategoryModel[]>()
     const all = async () => {
       pageResult.value = await getArticleList()
     }
     return { all, pageResult }
   }
   ```

## 8.时间处理

1. `article`表添加新的字段` createdAt`和`updatedAt`

   ```prisma

   model article {
     id         Int      @id @default(autoincrement()) @db.UnsignedInt
     title      String
     content    String   @db.Text
     category   category @relation(fields: [categoryId], references: [id])
     categoryId Int      @db.UnsignedInt
     createdAt  DateTime @default(now())
     updatedAt  DateTime @updatedAt
   }
   ```

2. 依次执行`npx prisma migrate dev`和`npx prisma migrate reset`重新生成数据

3. 全局注册序列化响应装饰器：全局注册之后可以不用单独使用` @SerializeOptions({ strategy: 'excludeAll' })`

   ```typescript
    /**
      * 注册序列化响应
      */
     app.useGlobalInterceptors(new ClassSerializerInterceptor(app.get(Reflector)))
   ```

4. 使用序列化装饰器

   ```typescript
     @Get()
     @SerializeOptions({ strategy: 'excludeAll' })
     findAll() {
       return this.articleService.findAll()
     }
   ```

5. 在`src\article\entities\article.entity.ts`使用实体类来处理数据：默认情况下让所有字段不返回，而是经过实体类处理再返回

   ```typescript
    @Get(':id')
     @SerializeOptions({ strategy: 'excludeAll' })
     async findOne(@Param('id') id: string) {
       const article = await this.articleService.findOne(+id)
       return new Article(article)
     }
   ```

6. 可以不使用`@SerializeOptions({ strategy: 'excludeAll' })`来处理，而是在实体类`article`中单独对每个字段进行处理

   ```typescript
   import { article } from '@prisma/client'
   import { Exclude, Transform } from 'class-transformer'
   
   export class Article {
     /**
      * 标题不返回
      */
     @Exclude()
     /**
      * 使用@Transform()装饰器进行数据处理
      */
     @Transform(({ value }) => {
       return value + ''
     })
     title: string
     constructor(options: Partial<article>) {
       //将this和options对象的所有属性合并
       Object.assign(this, options)
     }
   }
   
   ```

7. 序列化处理时间返回给前端

   ```typescript
   import { article } from '@prisma/client'
   import { Transform } from 'class-transformer'
   import dayjs from 'dayjs'
   export class Article {
     @Transform(({ value }) => dayjs(value).format('YYYY-mm-dd'))
     createdAt: string
     @Transform(({ value }) => dayjs(value).format('YYYY-mm-dd'))
     updatedAt: string
     constructor(options: Partial<article>) {
       //将this和options对象的所有属性合并
       Object.assign(this, options)
     }
   }
   ```

8. **当前端更新文章时，更新的时间就会有prisma数据库来自动维护，不需要重新序列化时间**

