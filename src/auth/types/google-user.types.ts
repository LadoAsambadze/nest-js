import { ObjectType, Field } from '@nestjs/graphql';

@ObjectType()
export class GoogleUserData {
    @Field(() => String)
    email: string;

    @Field(() => String)
    firstname: string;

    @Field(() => String)
    lastname: string;

    @Field(() => String, { nullable: true })
    avatar?: string | null;

    @Field(() => String)
    googleId: string;

    @Field(() => String)
    accessToken?: string;

    @Field(() => String)
    refreshToken?: string;
}
