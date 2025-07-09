import { ObjectType, Field } from '@nestjs/graphql';
import { User } from './user.type';
import { AuthTokens } from './auth-tokens.type';

@ObjectType()
export class AuthResponse {
    @Field(() => User)
    user: User;

    @Field(() => AuthTokens)
    tokens: AuthTokens;
}
