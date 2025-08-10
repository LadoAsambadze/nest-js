import { ObjectType, Field } from '@nestjs/graphql';
import { User } from './user.type';

@ObjectType()
export class RefreshTokenResponse {
    @Field()
    accessToken: string;

    @Field(() => User)
    user: User;
}
