import { IsEmail, IsString, IsStrongPassword } from "class-validator";

export class RegisterUserDto {

    @IsString()
    sName   : string;

    @IsString()
    @IsEmail()
    sEmail      : string;
    
    @IsString()
    @IsStrongPassword()
    sPassword   : string;
}