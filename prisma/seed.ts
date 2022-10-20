import { PrismaClient } from '@prisma/client'
import { hash } from 'argon2'
import { Random } from 'mockjs'
import _ from 'lodash'
const prisma = new PrismaClient()

async function run() {
  /**
   * prisma在创建数据，以及使用argon2对密码进行加密时都是异步任务需要同步等待
   */
  await prisma.user.create({
    data: {
      name: 'admin',
      password: await hash('admin123'),
      role: 'admin',
    },
  })

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
}
run()
