import { ObjectType, Field } from '@nestjs/graphql';

@ObjectType()
export class AccessTokenOutput {
    @Field()
    accessToken: string;
}
