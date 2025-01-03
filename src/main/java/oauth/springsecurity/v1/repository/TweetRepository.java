package oauth.springsecurity.v1.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import oauth.springsecurity.v1.entities.Tweet;

@Repository
public interface TweetRepository extends JpaRepository<Tweet, Long> {
	}
