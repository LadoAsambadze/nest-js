import { ObjectType, Field } from '@nestjs/graphql';

@ObjectType()
export class AuthTokens {
    @Field(() => String)
    accessToken: string;

    @Field(() => String)
    refreshToken: string;
}
