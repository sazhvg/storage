package ua.in.storage.repository;

import ua.in.storage.model.Post;
import ua.in.storage.model.Subreddit;
import ua.in.storage.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PostRepository extends JpaRepository<Post, Long> {
    List<Post> findAllBySubreddit(Subreddit subreddit);

    List<Post> findByUser(User user);

    List<Post> findAll();
}
