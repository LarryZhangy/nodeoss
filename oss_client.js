/*
 * nodeoss: OSS(Open Storage Services) NODE.JS SDK v0.1
 *
 * Authors:
 * Zhang Yong <joraye.zhangy at aliyun-inc.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 */

var fs = require('fs')
var path = require('path')
var util = require('util')
var crypto = require('crypto');
var xml2js = require('xml2js');
var request = require('request');
var mimetypes = require('./mimetypes');

function OssClient (options) {
    this._accessId = options.accessId;
    this._accessKey = options.accessKey;
    this._host = "storage.aliyun.com";
    this._port = "8080";
    this._timeout = 30000000;
};


/**
 * get the Authorization header
 *
 * "Authorization: OSS " + AccessId + ":" + base64(hmac-sha1(METHOD + "\n"
 * + CONTENT-MD5 + "\n"
 * + CONTENT-TYPE + "\n"
 * + DATE + "\n"
 * + CanonicalizedOSSHeaders
 * + Resource))
 */

OssClient.prototype.getSign = function (method, contentType, contentMd5, date, metas, resource) {
    var params = [
        method,
        contentType || '',
        contentMd5 || '',
        date
    ];

    // sort the metas
    if (metas) {
        var metaSorted = Object.keys(metas).sort();
        for(var i = 0, len = metaSorted.length; i < len; i++) {
            var k = metaSorted[i];
            params.push(k.toLowerCase() + ':' + metas[k]);
        }
    }

    params.push(resource);
    debug(params);
    
    var basicString = crypto.createHmac('sha1', this._accessKey);
    
    basicString.update(params.join('\n'));

    return 'OSS ' + this._accessId + ':' + basicString.digest('base64'); 
};

OssClient.prototype.getResource = function (ossParams){
    var resource = '';

    if (typeof ossParams['bucket'] === 'string') {
       resource = '/' + ossParams['bucket']; 
    }

    if (typeof ossParams['object'] === 'string') {
        resource = resource + '/' + ossParams['object'];
    }

    if (typeof ossParams['isAcl'] === 'boolean') {
       resource = resource + '?acl'; 
    }

    if (typeof ossParams['isGroup'] === 'boolean') {
       resource = resource + '?group'; 
    }
    
    return resource;
};

OssClient.prototype.getUrl = function (ossParams) {
    var url = 'http://' + this._host + ':' + this._port,
        params = [];

    if (typeof ossParams['bucket'] === 'string') {
        url = url + '/' + ossParams['bucket'];
    }

    if (typeof ossParams['object'] === 'string') {
        url = url + '/' + ossParams['object'];
    }
    
    if (typeof ossParams['prefix'] === 'string') {
        params.push('prefix=' + ossParams['prefix']);
    }

    if (typeof ossParams['marker'] === 'string') {
        params.push('marker=' + ossParams['marker']);
    }

    if (typeof ossParams['maxKeys'] === 'string') {
        params.push('max-keys=' + ossParams['maxKeys']);
    }

    if (typeof ossParams['delimiter'] === 'string') {
        params.push('delimiter='+ ossParams['delimiter']);
    }

    if (params.length > 0) {
        url = url + '?' + params.join('&');
    }

    if (typeof ossParams['isAcl'] === 'boolean') {
        url = url + '?acl';
    }

    if (typeof ossParams['isGroup'] === 'boolean') {
        url = url + '?group';
    }

    return url;
};

OssClient.prototype.getHeaders = function (method, metas, ossParams) {
    var date = new Date().toGMTString();

    var headers = {
        Date: date
    };
    
    if (ossParams.srcFile) {
        headers['content-type'] = mimetypes.lookup(path.extname(ossParams.srcFile));
        headers['content-Length'] = fs.statSync(ossParams.srcFile).size;
        
        var md5 = crypto.createHash('md5');
        md5.update(fs.readFileSync(ossParams.srcFile));
        headers['content-Md5'] = md5.digest('hex');
    }

    if (ossParams.isGroup) {
        headers['content-type'] = "txt/xml";
    }

    if (ossParams.userMetas) {
        metas = metas || {}
        for (i in ossParams.userMetas) {
            metas[i] = ossParams.userMetas[i];
        }
    }

    for (var i in metas) {
        headers[i] = metas[i];
    }

    for (var i in ossParams.userHeaders) {
        headers[i] = ossParams.userHeaders[i];
    }

    var resource = this.getResource(ossParams);
    headers['Authorization'] = this.getSign( method /* http request method */
                                            , headers['content-Md5']
                                            , headers['content-type'] 
                                            , date  /* date of now */
                                            , metas /* oss metas headers */
                                            , resource /* http request resource */
                                            );
    return headers;
};

OssClient.prototype.doRequest = function (method, metas, ossParams, callback) {
    var options = {};
    options.method = method;
    options.url = this.getUrl(ossParams);
    options.headers = this.getHeaders(method, metas, ossParams);
    options.timeout = this._timeout;

    debug(ossParams);
    debug(options);

    if (ossParams.isGroup) {
        options.body = this.getObjectGroupPostBody(ossParams.bucket, ossParams.objectArray);
    }

    var req = request(
        options
        , function (error, response, body) {
            if (error && callback) return callback(error);
            if (response.statusCode != 200 && response.statusCode != 204) {
                var e = new Error(body);
                e.code = response.statusCode;
                if (callback) callback(e);
            } else {
                // if we should write the body to a file, we will do it later
                if (body && !ossParams.dstFile) {
                    var parser = new xml2js.Parser();
                    parser.parseString(body, function(error, result) {
                        // console.log(util.inspect(result, false, null));
                        callback(error, result);
                    });
                } else {
                    if (method == 'HEAD') callback(error, response.headers);
                }
            }
        }
    );
    
    // put a file to oss
    if (ossParams.srcFile) {
        var rstream = fs.createReadStream(ossParams.srcFile);
        rstream.pipe(req);
    }

    // get a object from oss and save as a file
    if (ossParams.dstFile) {
        var wstream = fs.createWriteStream(ossParams.dstFile);
        req.pipe(wstream);
    }

};

/*********************/
/** bucket operater **/
/*********************/

OssClient.prototype.createBucket = function (bucket, acl, callback) {
    if (!bucket || !acl) {
        throw new Error('error arguments!');
    }

    var method = 'PUT';
    var metas = {'X-OSS-ACL': acl};
    var ossParams = {
        bucket: bucket
    };
    this.doRequest(method, metas, ossParams, callback);
};

OssClient.prototype.listBucket = function (callback) {
    var method = 'GET';
    var ossParams = {
        bucket: ''
    };

    this.doRequest(method, null, ossParams, callback);
};

OssClient.prototype.deleteBucket = function (bucket, callback) {
    if (!bucket) {
        throw new Error('error arguments!');
    }

    var method = 'DELETE';
    var ossParams = {
        bucket: bucket
    };

    this.doRequest(method, null, ossParams, callback);
};

OssClient.prototype.getBucketAcl = function (bucket, callback) {
    if (!bucket) {
        throw new Error('error arguments!');
    }

    var method = 'GET';
    var ossParams = {
          bucket: bucket
        , isAcl: true
    };

    this.doRequest(method, null, ossParams, callback);
};

OssClient.prototype.setBucketAcl = function (bucket, acl, callback) {
    if (!bucket || !acl) {
        throw new Error('error arguments!');
    }

    var method = 'PUT';
    var metas = {'X-OSS-ACL': acl};
    var ossParams = {
          bucket: bucket
    };

    this.doRequest(method, metas, ossParams, callback);
};

/*********************/
/** object operater **/
/*********************/

OssClient.prototype.putObject = function (bucket, object, srcFile, /* userMetas,*/ callback) {
    if (!bucket || !object || !srcFile) {
        throw new Error('error arguments!');
    }

    var that = this;
    fs.stat(srcFile, function(err, stats) {
        if (err) return callback(err); 

        var method = 'PUT';
        var ossParams = { 
            bucket: bucket
          , object: object
          , srcFile: srcFile
        };

        if (typeof arguments[3] == 'object') {
            ossParams.userMetas = arguments[3];
        }
        var callback = arguments[arguments.length-1];

        that.doRequest(method, null, ossParams, callback);
    });
};

OssClient.prototype.copyObject = function (bucket, dstObject, srcObject, callback) {
    if (!bucket || !dstObject || !srcObject) {
        throw new Error('error arguments!');
    }

    var method = 'PUT';
    var ossParams = { 
        bucket: bucket
      , object: dstObject
    };  

    var metas = { 'x-oss-copy-source': '/' + bucket + '/' + srcObject };

    this.doRequest(method, metas, ossParams, callback);
};

OssClient.prototype.deleteObject = function (bucket, object, callback) {
    if (!bucket || !object) {
        throw new Error('error arguments!');
    }

    var method = 'DELETE';
    var ossParams = { 
        bucket: bucket
      , object: object
    };  

    this.doRequest(method, null, ossParams, callback);
};

OssClient.prototype.getObject = function (bucket, object, dstFile, /* userHeaders , */ callback) {
    if (!bucket || !object || !dstFile) {
        throw new Error('error arguments!');
    }

    var method = 'GET';
    var ossParams = { 
        bucket: bucket
      , object: object
      , dstFile: dstFile
    };  

    if (typeof arguments[3] === 'object') {
        ossParams.userHeaders = arguments[3];
    }
    var callback = arguments[arguments.length-1];

    this.doRequest(method, null, ossParams, callback);
};

OssClient.prototype.headObject = function (bucket, object, callback) {
    if (!bucket || !object) {
        throw new Error('error arguments!');
    }

    var method = 'HEAD';
    var ossParams = { 
        bucket: bucket
      , object: object
    };  

    this.doRequest(method, null, ossParams, callback);
};

OssClient.prototype.listObject = function (bucket /*, prefix, marker, delimiter, maxKeys */, callback) {
    if (!bucket) {
        throw new Error('error arguments!');
    }
    
    var method = 'GET';
    var ossParams = { 
        bucket: bucket
    };
    
    ossParams.prefix = arguments[1] ? arguments[1] : null;
    ossParams.marker = arguments[2] ? arguments[2] : null;
    ossParams.delimiter = arguments[3] ? arguments[3] : null;
    ossParams.maxKeys = arguments[4] ? arguments[4] : null;
    var callback = arguments[arguments.length-1];

    this.doRequest(method, null, ossParams, callback);
};
/***************************/
/** object group operater **/
/***************************/

OssClient.prototype.getObjectEtag = function (object) {
    var md5 = crypto.createHash('md5');
    md5.update(fs.readFileSync(object));
    return md5.digest('hex').toUpperCase();
};

OssClient.prototype.getObjectGroupPostBody = function (bucket, objectArray, callback) {
    var xml = '<CreateFileGroup>';
    var index = 0;
    
    for (i in objectArray) {
        index ++;
        var etag = this.getObjectEtag(objectArray[i]);
        xml += '<Part>';
        xml += '<PartNumber>' + index + '</PartNumber>';
        xml += '<PartName>' + objectArray[i] + '</PartName>';
        xml += '<ETag>' + etag + '</ETag>';
        xml += '</Part>';
    }

    xml += '</CreateFileGroup>';
    return xml;
};

OssClient.prototype.createObjectGroup = function (bucket, objectGroup, objectArray, callback) {
    if (!bucket || !objectGroup || !objectArray) {
        throw new Error('error arguments!');
    }

    var method = 'POST';
    var ossParams = { 
        bucket: bucket
      , object: objectGroup
      , objectArray: objectArray
      , isGroup: true
    };  
    
    this.doRequest(method, null, ossParams, callback);
};

OssClient.prototype.getObjectGroup = function (bucket, objectGroup, dstFile, callback) {
    if (!bucket || !objectGroup || !dstFile) {
        throw new Error('error arguments!');
    }

    var method = 'GET';
    var ossParams = { 
        bucket: bucket
      , object: objectGroup
      , isGroup: true
      , dstFile: dstFile
    };  

    this.doRequest(method, null, ossParams, callback);
}; 

OssClient.prototype.getObjectGroupIndex = function (bucket, objectGroup, callback) {
    if (!bucket || !objectGroup) {
        throw new Error('error arguments!');
    }

    var method = 'GET';
    var ossParams = { 
        bucket: bucket
      , object: objectGroup
    };
    var metas = {'X-OSS-FILE-GROUP': ''};

    this.doRequest(method, metas, ossParams, callback);
}; 

OssClient.prototype.headObjectGroup = function (bucket, objectGroup, callback) {
    if (!bucket || !objectGroup) {
        throw new Error('error arguments!');
    }

    var method = 'HEAD';
    var ossParams = { 
        bucket: bucket
      , object: objectGroup
    };  

    this.doRequest(method, null, ossParams, callback);
};

OssClient.prototype.deleteObjectGroup = function (bucket, objectGroup, callback) {
    if (!bucket || !objectGroup) {
        throw new Error('error arguments!');
    }

    var method = 'DELETE';
    var ossParams = { 
        bucket: bucket
      , object: objectGroup
    };  

    this.doRequest(method, null, ossParams, callback);
};

var debugLevel = process.env['NODE_DEBUG_OSSCLIENT'] ? 1 : 0;
function debug (x) {
  if (debugLevel > 0) console.log(x);
}

exports.OssClient = OssClient;
