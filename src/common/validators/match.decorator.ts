import {
  ValidationArguments,
  ValidationOptions,
  registerDecorator
} from 'class-validator';

export function Match(property: string, validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      constraints: [property],
      name: 'Match',
      options: validationOptions,
      propertyName: propertyName,
      target: object.constructor,
      validator: {
        defaultMessage(args: ValidationArguments) {
          return `${args.property} must match ${args.constraints[0]}`;
        },
        validate(value: any, args: ValidationArguments) {
          console.log(value, args);
          const [relatedPropertyName] = args.constraints;
          const relatedValue = (args.object as any)[
            relatedPropertyName as string
          ];
          return value === relatedValue;
        }
      }
    });
  };
}
