import { Body, Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHello(): string {
    return 'Hello World!';
  }

  create(title: string): string {
    return `"Here": ${title}`;
  }

  getProfile() {
    return { id: 1, email: 'mai@mail.com' };
  }
}
