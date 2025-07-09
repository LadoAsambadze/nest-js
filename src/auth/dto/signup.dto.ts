import {
    IsEmail,
    IsNotEmpty,
    IsString,
    Matches,
    MaxLength,
    MinLength,
    IsStrongPassword,
    IsOptional,
    IsUrl,
    IsPhoneNumber,
} from 'class-validator';
import { Transform } from 'class-transformer';
import { InputType, Field } from '@nestjs/graphql';

@InputType()
export class SignupRequest {
    @Field(() => String)
    @IsString({ message: 'First name must be a string' })
    @IsNotEmpty({ message: 'First name is required' })
    @Transform(({ value }) => value?.trim())
    @Matches(/^[a-zA-Z\s'-]+$/, {
        message:
            'First name can only contain letters, spaces, hyphens, and apostrophes',
    })
    @MinLength(2, { message: 'First name must be at least 2 characters long' })
    @MaxLength(50, { message: 'First name cannot exceed 50 characters' })
    firstname: string;

    @Field(() => String)
    @IsString({ message: 'Last name must be a string' })
    @IsNotEmpty({ message: 'Last name is required' })
    @Transform(({ value }) => value?.trim())
    @Matches(/^[a-zA-Z\s'-]+$/, {
        message:
            'Last name can only contain letters, spaces, hyphens, and apostrophes',
    })
    @MinLength(2, { message: 'Last name must be at least 2 characters long' })
    @MaxLength(50, { message: 'Last name cannot exceed 50 characters' })
    lastname: string;

    @Field(() => String)
    @IsString({ message: 'Email must be a string' })
    @IsNotEmpty({ message: 'Email is required' })
    @Transform(({ value }) => value?.trim().toLowerCase())
    @IsEmail({}, { message: 'Please provide a valid email address' })
    @MaxLength(255, { message: 'Email cannot exceed 255 characters' })
    email: string;

    @Field(() => String)
    @IsString({ message: 'Password must be a string' })
    @IsNotEmpty({ message: 'Password is required' })
    @MinLength(8, { message: 'Password must be at least 8 characters long' })
    @MaxLength(128, { message: 'Password cannot exceed 128 characters' })
    @IsStrongPassword(
        {
            minLength: 8,
            minLowercase: 1,
            minUppercase: 1,
            minNumbers: 1,
            minSymbols: 1,
        },
        {
            message:
                'Password must contain at least 8 characters with uppercase, lowercase, number, and special character',
        }
    )
    password: string;

    @Field(() => String, { nullable: true })
    @IsOptional()
    @IsUrl({}, { message: 'Avatar must be a valid URL' })
    avatar?: string;

    @Field(() => String, { nullable: true })
    @IsOptional()
    @IsPhoneNumber(undefined, { message: 'Phone must be a valid phone number' })
    phone?: string;
}
