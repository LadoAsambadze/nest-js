import { ObjectType, Field } from '@nestjs/graphql';

@ObjectType()
export class RefreshTokenValidation {
    @Field(() => String)
    userId: string;

    @Field(() => String)
    email: string;

    @Field(() => String)
    role: string;
}
