import { Field, InputType } from '@nestjs/graphql';

@InputType()
export class GoogleLoginRequest {
    @Field(() => String)
    firstname: string;

    @Field(() => String)
    lastname: string;

    @Field(() => String)
    email: string;

    @Field(() => String, { nullable: true })
    avatar?: string;

    @Field(() => String, { nullable: true })
    phone?: string;

    @Field(() => String)
    googleId: string;
}
