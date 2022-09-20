let obj={}
  const repos = async () => {
    const url = `https://api.github.com/users/Shikha291/repos`;

    let data = await fetch(url);

    let parseData = await data.json();
    for(let i=0;i<parseData.length;i++)
    {
      const name=parseData[i].name;
      // console.log(name)
      const url1 = `https://api.github.com/repos/Shikha291/${name}/languages`;
      let data1 = await fetch(url1);
      const language = await data1.json();
      obj = Object.assign(obj,language)
      // console.log(obj);
    }
    
  }
  export const youtube = async() =>{
      await repos();
      console.log(obj)
      const YOUTUBE_API_KEY = "AIzaSyA78Bfr50t93zRCpnypkxEUulcpGFdgIA0"
      for(let k in obj)
      {
          console.log("Ready to get Youtube data!");
          const url = `https://www.googleapis.com/youtube/v3/search?key=${YOUTUBE_API_KEY}&type=video&part=snippet&q=${k}`;
        
          const response = await fetch(url);
          const data = await response.json();
          const items = data.items
          for(let i=0;i<items.length;i++)
          {
            let url1 = `https://www.youtube.com/watch?v=${items[i].id.videoId}`;
            console.log(url1)
          }
      }
  }

