import { ObjectType, Field, ID } from '@nestjs/graphql';

@ObjectType()
export class User {
    @Field(() => ID)
    id: string;

    @Field(() => String)
    firstname: string;

    @Field(() => String)
    lastname: string;

    @Field(() => String)
    email: string;

    @Field(() => String)
    role: string;

    @Field(() => Boolean)
    isVerified: boolean;

    @Field(() => Boolean)
    isActive: boolean;

    @Field(() => String, { nullable: true })
    avatar?: string | null;

    @Field(() => String, { nullable: true })
    phone?: string | null;

    @Field(() => Date)
    createdAt: Date;

    @Field(() => Date)
    updatedAt: Date;

    @Field(() => Date, { nullable: true })
    lastLogin?: Date | null;
}
