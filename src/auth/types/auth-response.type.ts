import { ObjectType, Field } from '@nestjs/graphql';
import { User } from './user.type';

@ObjectType()
export class AuthResponse {
    @Field(() => User)
    user: User;

    @Field(() => String)
    accessToken: string;
}
