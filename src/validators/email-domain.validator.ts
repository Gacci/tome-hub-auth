// validators/email-domain.validator.ts
import { ValidationOptions, registerDecorator } from 'class-validator';

import { College } from '../colleges/models/college.model';

export function IsDomainExists(validationOptions?: ValidationOptions) {
  return function (object: { [key: string]: any }, propertyName: string) {
    registerDecorator({
      constraints: [],
      name: 'IsDomainExists',
      options: validationOptions,
      propertyName: propertyName,
      target: object.constructor,
      validator: {
        async validate(value: string) {
          if (!value) return false;

          const emailDomain = value
            .replace(/.+@/g, '')
            .split('.')
            .slice(-2)
            .join('.');

          // Call the Colleges service to check if the domain exists
          return !!(await College.exists({ emailDomain }));
        }
      }
    });
  };
}
