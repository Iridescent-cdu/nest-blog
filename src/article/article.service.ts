import { PrismaService } from '@/prisma/prisma.service'
import { Injectable } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { CreateArticleDto } from './dto/create-article.dto'
import { UpdateArticleDto } from './dto/update-article.dto'

@Injectable()
export class ArticleService {
  constructor(private prisma: PrismaService, private config: ConfigService) {}

  create(createArticleDto: CreateArticleDto) {
    return this.prisma.article.create({
      data: {
        title: createArticleDto.title,
        content: createArticleDto.content,
        categoryId: +createArticleDto.categoryId,
      },
    })
  }

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
        page_row: +row,
        total,
        total_page: Math.ceil(total / row),
      },
      data: articles,
    }
  }

  findOne(id: number) {
    return this.prisma.article.findFirst({
      where: {
        id,
      },
    })
  }

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

  remove(id: number) {
    return this.prisma.article.delete({
      where: {
        id,
      },
    })
  }
}
