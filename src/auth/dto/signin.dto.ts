import { Field, InputType } from '@nestjs/graphql';

@InputType()
export class SigninRequest {
    @Field(() => String)
    email: string;

    @Field(() => String)
    password: string;
}
