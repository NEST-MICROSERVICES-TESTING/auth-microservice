import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcrypt';
import { PrismaClient } from '@prisma/client';
import { RegisterUserDto } from './dto';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
    
    private readonly logger = new Logger('AuthService');

    onModuleInit() {        
        this.$connect();
        this.logger.log('MongoDB connected');
    }

    async registerUser( registerUserDto:RegisterUserDto ){

        const { sEmail, sName, sPassword } = registerUserDto;

        try {
            
            const user = await this.user.findUnique({
                where: {
                    sEmail: sEmail
                }
            });

            if ( user ){
                throw new RpcException({
                    status  : 400
                    ,message: 'User already exists'
                });
            }

            const newUser = await this.user.create({
                data:{
                    sEmail      : sEmail
                    ,sPasssword : bcrypt.hashSync(sPassword, 10) // TODO  encriptar // Hash
                    ,sName      : sName
                }
            });

            const { sPasssword: __, ...rest } = newUser;

            return {
                user    : rest
                ,token  : 'ABC'
            }



        } catch (error) {
            throw new RpcException({
                status  : 400
                ,message: error.message
            })
        }
    }

}
