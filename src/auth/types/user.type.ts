import { ObjectType, Field, ID } from '@nestjs/graphql';

@ObjectType()
export class User {
    @Field(() => ID)
    id: string;

    @Field()
    firstname: string;

    @Field()
    lastname: string;

    @Field()
    email: string;

    @Field()
    role: string;

    @Field()
    isVerified: boolean;

    @Field()
    isActive: boolean;

    @Field(() => String, { nullable: true })  
    avatar?: string | null;

    @Field(() => String, { nullable: true })  
    phone?: string | null;

    @Field()
    createdAt: Date;

    @Field()
    updatedAt: Date;

    @Field(() => Date, { nullable: true })  
    lastLogin?: Date | null;
}
