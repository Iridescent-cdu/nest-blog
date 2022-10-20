import { IsNotEmpty } from 'class-validator'

export class CreateCategoryDto {
  @IsNotEmpty({ message: '栏目标题不能为空' })
  title: string
}
