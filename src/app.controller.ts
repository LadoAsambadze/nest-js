import { Resolver, Query } from '@nestjs/graphql';

@Resolver()
export class AppResolver {
    @Query(() => String, { name: 'hello' })
    hello(): string {
        return 'Hello World!';
    }
}
