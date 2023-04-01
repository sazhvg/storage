package ua.in.storage.mapper;

import ua.in.storage.dto.CommentsDto;
import ua.in.storage.model.Comment;
import ua.in.storage.model.Post;
import ua.in.storage.model.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;


@Mapper(componentModel = "spring")
public interface CommentMapper {
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "text", source = "commentsDto.text")
    @Mapping(target = "createdDate", expression = "java(java.time.Instant.now())")
//    @Mapping(target = "post", source = "post")
//    @Mapping(target = "user", source = "user")
    Comment map(CommentsDto commentsDto, Post post, User user);

    @Mapping(target = "postId", expression = "java(comment.getPost().getPostId())")
    @Mapping(target = "userName", expression = "java(comment.getUser().getEmail())")
    CommentsDto mapToDto(Comment comment);
}