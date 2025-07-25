import {
  Controller,
  Get,
  Param,
  ParseIntPipe,
  Query,
  UseGuards
} from '@nestjs/common';

import { InternalGuard } from '../guards/internal/internal.guard';
import { SearchUsersDto } from './dto/search-user.dto';
import { UserService } from './user.service';

@UseGuards(InternalGuard)
@Controller('users')
export class UsersController {
  constructor(private readonly users: UserService) {}

  @Get('search')
  async search(@Query() query: SearchUsersDto) {
    return await this.users.search(query);
  }

  @Get(':userId')
  findOne(@Param('userId', ParseIntPipe) userId: number) {
    return this.users.findOne(userId);
  }
}
