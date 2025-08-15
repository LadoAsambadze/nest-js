import { InputType, Field } from '@nestjs/graphql';

@InputType()
export class UpdatePasswordInput {
    @Field()
    password: string;

    @Field()
    token: string;
}
