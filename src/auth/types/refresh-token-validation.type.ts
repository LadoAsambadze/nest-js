import { ObjectType, Field } from '@nestjs/graphql';

@ObjectType()
export class RefreshTokenValidation {
    @Field()
    userId: string;

    @Field()
    email: string;

    @Field()
    role: string;
}
