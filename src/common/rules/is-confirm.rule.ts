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
