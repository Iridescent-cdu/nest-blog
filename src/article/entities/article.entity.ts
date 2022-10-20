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
