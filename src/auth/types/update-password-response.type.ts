import { ObjectType, Field } from '@nestjs/graphql';

@ObjectType()
export class UpdatePasswordResponse {
    @Field()
    message: string;
}
