import { Field, ObjectType } from '@nestjs/graphql';

@ObjectType()
export class SignupResponse {
    @Field()
    success: boolean;

    @Field()
    message: string;

    @Field({ nullable: true })
    userId?: string;

    @Field({ nullable: true })
    email?: string;
}
