import React, { useState, useEffect } from "react";
import PropTypes from "prop-types";
import Post from "./post";
import InfiniteScroll from 'react-infinite-scroll-component';

export default function MyApp({ url }) {
    const [results, setResults] = useState([]);
    const [next, setNext] = useState("");
    const [hasMore, setHasMore] = useState(true);

    useEffect(() => {
    let ignoreStaleRequest = false;

    fetch(url, { credentials: "same-origin" })
        .then((response) => {
        if (!response.ok) throw Error(response.statusText);
        return response.json();
        })
        .then((data) => {
        if (!ignoreStaleRequest) {
            console.log("Fetched data: ", data);
            setResults(data.results);
            if (data.next) {
                setNext(data.next);
            } else {
                setHasMore(false); // No more posts to load
            }
        }
        })
        .catch((error) => console.log(error));

    return () => {
        ignoreStaleRequest = true;
    };
    }, [url]);

    const fetchData = async () => {
        if(!next) return;

        try {
            const response = await fetch(next);
            const data = await response.json();
      
            // Update the posts state and append new posts
            setResults((prevPosts) => [...prevPosts, ...data.results]);
      
            // Update the nextUrl state with the next batch URL
            if (data.next) {
              setNext(data.next);
            } else {
              setHasMore(false); // No more posts to load
            }
          } catch (error) {
            console.error('Error fetching posts:', error);
            setHasMore(false); // Stop fetching more data on error
          }
    };

    const listPosts = results.map(result =>
        <li key={result.postid}>
            <Post url={result.url}/>
        </li>
    )

    return (
        <InfiniteScroll
          dataLength={results.length} // Length of the current posts array
          next={fetchData} // Function to fetch more data
          hasMore={hasMore} // Whether there are more posts to load
          loader={<h4>Loading...</h4>} // Display while loading new data
          endMessage={
            <p style={{ textAlign: 'center' }}>
              <b>Yay! You have seen it all</b>
            </p>
          }
        >
        <ul>{listPosts}</ul>
        </InfiniteScroll>
      );
}

MyApp.propTypes = {
    url: PropTypes.string.isRequired,
  };