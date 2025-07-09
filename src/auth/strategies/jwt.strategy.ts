// import { Injectable, UnauthorizedException } from '@nestjs/common';
// import { PassportStrategy } from '@nestjs/passport';
// import { ExtractJwt, Strategy } from 'passport-jwt';
// import { PrismaService } from 'src/prisma/prisma.service';
// import { ConfigService } from '@nestjs/config';

// interface JwtPayload {
//     sub: string;
//     email: string;
//     role: string;
//     iat?: number;
//     exp?: number;
// }

// @Injectable()
// export class JwtStrategy extends PassportStrategy(Strategy) {
//     constructor(
//         private prisma: PrismaService,
//         private config: ConfigService
//     ) {
//         super({
//             jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
//             ignoreExpiration: false,
//             secretOrKey: config.get('JWT_SECRET'),
//         });
//     }

//     async validate(payload: JwtPayload) {
//         const user = await this.prisma.user.findUnique({
//             where: { id: payload.sub },
//             select: {
//                 id: true,
//                 firstname: true,
//                 lastname: true,
//                 email: true,
//                 role: true,
//                 isVerified: true,
//                 isActive: true,
//                 avatar: true,
//                 phone: true,
//                 createdAt: true,
//                 updatedAt: true,
//                 lastLogin: true,
//             },
//         });

//         if (!user) {
//             throw new UnauthorizedException('User not found');
//         }

//         if (!user.isActive) {
//             throw new UnauthorizedException('Account is deactivated');
//         }

//         return user;
//     }
// }
