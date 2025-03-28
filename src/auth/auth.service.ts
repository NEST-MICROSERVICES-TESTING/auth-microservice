import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcrypt';
import { PrismaClient } from '@prisma/client';
import { RegisterUserDto } from './dto';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
    
    private readonly logger = new Logger('AuthService');

    constructor(
        private readonly jwtService: JwtService
    ){
        super();
    }

    onModuleInit() {        
        this.$connect();
        this.logger.log('MongoDB connected');
    }

    async signJWT( payload: JwtPayload ){
        return this.jwtService.sign( payload );
    }

    async verifyToken( token:string ){
        try {
        
            const { sub, iat, exp, ... user } = this.jwtService.verify( token, {
                secret: envs.jwtSecret
            });

            return {
                user    : user
                ,token  : await this.signJWT(user) 
            }
            
        } catch (error) {
            console.log( error );
            throw new RpcException({
                status  : 401
                ,message: 'Invalid Token'
            });
        }
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
                ,token  : await this.signJWT( rest )
            }



        } catch (error) {
            throw new RpcException({
                status  : 400
                ,message: error.message
            });
        }
    }


    async loginUser( loginUserDto:LoginUserDto ) {
        const { sEmail, sPassword } = loginUserDto;

        try {
            
            const user = await this.user.findUnique({
                where: {
                    sEmail: sEmail
                }
            });

            if ( !user ){
                throw new RpcException({
                    status  : 400
                    ,message: 'User/Password not valid'
                });
            }

            const isPasswordValid = bcrypt.compareSync( sPassword, user.sPasssword );
            if( !isPasswordValid ) {
                throw new RpcException({
                    status  : 400
                    ,message: 'User/Password not valid'
                });
            }

            const { sPasssword: __, ...rest } = user;

            return {
                user    : rest
                ,token  : await this.signJWT( rest )
            }


        } catch (error) {
            throw new RpcException({
                status  : 400
                ,message: error.message
            });
        }
    }

}
