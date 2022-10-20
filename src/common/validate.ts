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
