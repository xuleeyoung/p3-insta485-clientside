import React, { useState, useEffect } from "react";
import PropTypes from "prop-types";
import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";
import utc from "dayjs/plugin/utc";

dayjs.extend(relativeTime);
dayjs.extend(utc);


function Likes({ likes = {}, handleNumLikes }) {
    return (
        <div>
            <button data-testid="like-unlike-button" onClick={handleNumLikes}>
                {likes.lognameLikesThis ? 'unlike' : 'like'}
            </button>
            <br />
            <div>
                <p>{likes.numLikes}</p> <p>{likes.numLikes == 1? 'like' : 'likes'}</p>
            </div>
        </div>
    )
}

function Comments({ comments = [], handleDeleteComment, handlePostComment }) {
    const [commentText, setCommentText] = useState("");

    const listComments = comments.map(comment =>
        <li key={comment.commentid}>
            <a href={comment.ownerShowUrl}><b>{comment.owner}</b></a>
            <span data-testid="comment-text">{comment.text}</span>
            {comment.lognameOwnsThis &&
            <button data-testid="delete-comment-button" onClick={() => handleDeleteComment(comment.url, comment.commentid)}>
                Delete Comment
            </button>
            }
        </li>
    )

    const handleKeyDown = (e) => {
        if(e.key === "Enter") {
            e.preventDefault();
            handlePostComment(commentText);
            setCommentText("");
        }
    };

    return (
        <div>
            <ul>{listComments}</ul>
            <form data-testid="comment-form">
                <input 
                    type="text" 
                    value={commentText} 
                    onChange={(e) => setCommentText(e.target.value)}
                    onKeyDown={handleKeyDown}
                />
            </form>
        </div>
    )
}

// The parameter of this function is an object with a string called url inside it.
// url is a prop for the Post component.
export default function Post({ url }) {
  /* Display image and post owner of a single post */

  const [posts, setPosts] = useState({});
  const [loading, setLoading] = useState(true);
  const [savedClick, setSavedClick] = useState(false);
  const [savedComment, setSavedComment] = useState("");

  useEffect(() => {
    // Declare a boolean flag that we can use to cancel the API request.
    let ignoreStaleRequest = false;

    // Call REST API to get the post's information
    fetch(url, { credentials: "same-origin" })
      .then((response) => {
        if (!response.ok) throw Error(response.statusText);
        return response.json();
      })
      .then((data) => {
        // If ignoreStaleRequest was set to true, we want to ignore the results of the
        // the request. Otherwise, update the state to trigger a new render.
        if (!ignoreStaleRequest) {
          console.log("Post data fetched: ", data);
          setPosts(data);
          setLoading(false);
        }
      })
      .catch((error) => console.log(error));

    return () => {
      // This is a cleanup function that runs whenever the Post component
      // unmounts or re-renders. If a Post is about to unmount or re-render, we
      // should avoid updating state.
      ignoreStaleRequest = true;
    };
  }, [url]);

  useEffect(() => {
    if(!loading) {
        console.log("Loading", loading)
        if(savedClick) handleNumLikes();
        if(savedComment) handlePostComment(savedComment);
    }
  }, [loading])

  function handleNumLikes(){
    if(loading) {
        setSavedClick(!savedClick);
        return;
    }
    if(posts.likes.lognameLikesThis) {
        setPosts({...posts, "likes": {"numLikes": posts.likes["numLikes"] - 1, "lognameLikesThis": false, "url": null}})
        fetch(`${posts.likes.url}`, {
            method: "DELETE",
            credentials: "same-origin",
        })
        .then((response) => {
            if (response.status === 204) {
                return null;
            }
            return response.json(); // Parse the response if it's not 204
        })
        .catch((error) => {
            console.error("Error unliking the post:", error);
        });
    }
    else {
        fetch(`/api/v1/likes/?postid=${posts.postid}`, {
            method: "POST",
            credentials: "same-origin",
        })
        .then((response) => {
            if (!response.ok) {
                throw new Error("Failed to unlike the post");
            }
            return response.json();
        })
        .then((data) => {
            // On success, change the state to reflect the unlike
            setPosts({...posts, "likes": {"numLikes": posts.likes["numLikes"] + 1, "lognameLikesThis": true, "url": data.url}})
        })
        .catch((error) => {
            console.error("Error unliking the post:", error);
        });
    }
  }


  function handleDeleteComment(url, commentid) {
    fetch(url, {
        method: "DELETE",
        credentials: "same-origin",
    })
    .then((response) => {
        if (response.status === 204) {
            return null;
        }
        return response.json(); // Parse the response if it's not 204
    })
    .then(() => {
        setPosts((prevData) => ({
            ...prevData,
            "comments": prevData.comments.filter((item) => item.commentid !== commentid)
        }))
    })
    .catch((error) => {
        console.error("Error uncomment the post:", error);
    });
  }


  const handlePostComment = async (text) => {
    if(loading) {
        setSavedComment(text);
        return;
    }
    try {
        const response = await fetch(`/api/v1/comments/?postid=${posts.postid}`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ "text": text }), // Send the comment text
        });
  
        if (!response.ok) {
          throw new Error("Failed to post comment");
        }

        const data = await response.json(); // Parse the JSON response
        setPosts((prevData) => ({
            ...prevData,
            "comments": [...prevData.comments, data]
        }));
      } catch (error) {
        console.log("Error post comment:", error);
      }
  };


  const handleDoubleClick = () => {
    if(!posts.likes.lognameLikesThis) {
        fetch(`/api/v1/likes/?postid=${posts.postid}`, {
            method: "POST",
            credentials: "same-origin",
        })
        .then((response) => {
            if (!response.ok) {
                throw new Error("Failed to unlike the post");
            }
            return response.json();
        })
        .then((data) => {
            // On success, change the state to reflect the unlike
            setPosts({...posts, "likes": {"numLikes": posts.likes["numLikes"] + 1, "lognameLikesThis": true, "url": data.url}})
        })
        .catch((error) => {
            console.error("Error unliking the post:", error);
        });
    }
  }

  const humanReadableTime = dayjs.utc(posts.created).local().fromNow();

  // Render post image and post owner
  return (
    <div style={{ borderStyle: 'solid', borderWidth: '2px', borderColor: 'black' }}>
        <div style={{ color: 'black', textAlign: 'left', marginLeft: '100px', width: '50%', display: 'inline-block' }}>
        <a href={`/users/${posts.owner}/`}>
            <img className="user-image" src={posts.ownerImgUrl} alt="owner_image" style={{ width: '20%' }} />
            {posts.owner}
        </a>
        </div>

        <div style={{ color: 'black', textAlign: 'right', marginLeft: '100px', width: '50%', display: 'inline-block' }}>
            <a href={`/posts/${posts.postid}/`}>{humanReadableTime}</a>
        </div>

        <img 
            src={posts.imgUrl} 
            alt="post_image" 
            style={{ alignContent: 'center' }}
            onDoubleClick={handleDoubleClick}
        />
        <div>
            <Likes likes={posts.likes} handleNumLikes={handleNumLikes}/>
        </div>
        <div>
            <Comments comments={posts.comments} handleDeleteComment={handleDeleteComment} handlePostComment={handlePostComment}/>
        </div>
    </div>
  );
}

Post.propTypes = {
  url: PropTypes.string.isRequired,
};
