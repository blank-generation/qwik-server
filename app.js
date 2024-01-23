import express from 'express';
import axios from 'axios';
import cryptoJs from 'crypto-js';
import storage from 'node-persist';

const app = express();
const port = 3000;
storage.init();

const baseUrl = process.env.BASEURL;
const clientId = process.env.CLIENTID;
const clientSecret = process.env.CLIENTSEC;
const username = process.env.USER;
const password = process.env.PWD;

//  Get Authorization Code
async function getAuthorizationCode(baseOAuthUrl, clientId, username, password) {
    const verifyEndpoint = `${baseOAuthUrl}/oauth2/verify`;

    try {
        const response = await axios.post(verifyEndpoint, {
            clientId,
            username,
            password
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });

        const authorizationCode = response.data.authorizationCode;
        return authorizationCode;
    } catch (error) {
        console.error('Error getting authorization code:', error.message);
        return error.data;
    }
}

// Get Bearer Token
async function getBearerToken(baseOAuthUrl, clientId, clientSecret, authorizationCode) {
    const tokenEndpoint = `${baseOAuthUrl}/oauth2/token`;

    try {
        const response = await axios.post(tokenEndpoint, {
            clientId,
            clientSecret,
            authorizationCode
        }, {
            headers: {
                'Content-Type': 'application/json'
            }
        });

        const bearerToken = response.data.token;
        return bearerToken;
    } catch (error) {
        console.error('Error getting bearer token:', error.message);
        return error.data;
    }
}


// Generate Signature
function generateSignature(method, apiUrl, requestBody) {

    let absApiUrl = apiUrl;

    let sortObject = (object) => {
        if (object instanceof Array) {
            var sortedObj = [],
                keys = Object.keys(object);
        }
        else {
            sortedObj = {},
                keys = Object.keys(object);
        }

        keys.sort(function (key1, key2) {
            if (key1 < key2) return -1;
            if (key1 > key2) return 1;
            return 0;
        });

        for (var index in keys) {
            var key = keys[index];
            if (typeof object[key] == 'object' && !!object[key]) {
                if ((object[key] instanceof Array)) {
                    sortedObj[key] = sortObject(object[key]);
                }
                sortedObj[key] = sortObject(object[key]);
            } else {
                sortedObj[key] = object[key];
            }
        }
        return sortedObj;
    }

    let sortQueryParams = () => {
        let url = absApiUrl.split('?'),
            baseUrl = url[0],
            queryParam = url[1].split('&');

        absApiUrl = baseUrl + '?' + queryParam.sort().join('&');

        return fixedEncodeURIComponent(absApiUrl);
    }

    let getConcatenateBaseString = () => {
        let baseArray = [];
        baseArray.push(method.toUpperCase());

        if (absApiUrl.indexOf('?') >= 0) {
            baseArray.push(sortQueryParams());
        } else {
            baseArray.push(fixedEncodeURIComponent(absApiUrl));
        }
        if (requestBody) {
            baseArray.push(fixedEncodeURIComponent(JSON.stringify(sortObject(requestBody))));
        }

        return baseArray.join('&');
    }

    let fixedEncodeURIComponent = (str) => {
        return encodeURIComponent(str).replace(/[!'()*]/g, function (c) {
            return '%' + c.charCodeAt(0).toString(16).toUpperCase();
        });
    }

    const signature = cryptoJs.HmacSHA512(getConcatenateBaseString(), clientSecret);
    return signature;
}


app.get('/', async (req, res) => {

    const token = await storage.getItem('token');

    if (token) {
        res.send('Hello World!');

    } else {
        res.send('Not logged in');

    }
})

app.get('/get-auth', async (req, res) => {

    const authorizationCode = await getAuthorizationCode(baseUrl, clientId, username, password);
    // console.log('Authorization Code:', authorizationCode);


    const bearerToken = await getBearerToken(baseUrl, clientId, clientSecret, authorizationCode);
    // console.log('Bearer Token:', bearerToken);


    if (bearerToken?.message) {
        res.send({ "error": bearerToken?.message, });
    } else {
        await storage.setItem('token', bearerToken);
        res.send({ "success": true });
    }
})

app.get('/store-categories', async (req, res) => {
    const bearerToken = await storage.getItem('token');
    // console.log(bearerToken);
    if (!bearerToken) {
        res.send('Not logged in');
    } else {

        const categoriesEndpoint = `${baseUrl}/rest/v3/catalog/categories/`;
        const signature = generateSignature('get', categoriesEndpoint, null);
        const dateAtClient = new Date().toISOString();

        let responseText;
        try {
            const response = await axios.get(categoriesEndpoint, {
                headers: {
                    'Content-Type': 'application/json',
                    'dateAtClient': dateAtClient,
                    'signature': signature,
                    'Authorization': `Bearer ${bearerToken}`

                }
            });
            responseText = response?.data;
        } catch (error) {
            console.error('Error getting bearer token:', error.message);
            responseText = error;
        }
        if (responseText?.message) {
            res.send({ "error": responseText.message });
        } else {
            await storage.setItem('category_list', responseText);
            res.send(responseText);
        }
    }
})

app.get('/store-product-list', async (req, res) => {
    const bearerToken = await storage.getItem('token');
    // console.log(bearerToken);
    if (!bearerToken) {
        res.send('Not logged in');
    } else {

        const categoryList = await storage.getItem('category_list');
        let count = 0;
        if (Array.isArray(categoryList)) {
            let productList = [];
            await Promise.all(
                categoryList.map(async (category) => {

                    const endpoint = `${baseUrl}/rest/v3/catalog/categories/${category.id}`;
                    const signature = generateSignature('get', endpoint, null);
                    const dateAtClient = new Date().toISOString();

                    let responseText;
                    try {
                        const response = await axios.get(endpoint, {
                            headers: {
                                'Content-Type': 'application/json',
                                'dateAtClient': dateAtClient,
                                'signature': signature,
                                'Authorization': `Bearer ${bearerToken}`

                            }
                        });
                        responseText = response?.data;
                    } catch (error) {
                        console.error('Error getting bearer token:', error.message);
                        responseText = error;
                    }
                    if (!responseText?.message) {
                        await productList.push(responseText);
                        count += 1;
                    }

                })
                )
            if(productList?.length > 0){
                await storage.setItem("product_list", productList);
            }
        } else if (categoryList?.id) {
            const endpoint = `${baseUrl}/rest/v3/catalog/categories/${categoryList.id}`;
            const signature = generateSignature('get', endpoint, null);
            const dateAtClient = new Date().toISOString();

            let responseText;
            try {
                const response = await axios.get(endpoint, {
                    headers: {
                        'Content-Type': 'application/json',
                        'dateAtClient': dateAtClient,
                        'signature': signature,
                        'Authorization': `Bearer ${bearerToken}`

                    }
                });
                responseText = response?.data;
            } catch (error) {
                console.error('Error getting bearer token:', error.message);
                responseText = error;
            }
            if (!responseText?.message) {
                await storage.setItem("product_list", responseText);
                count += 1;
            }
        }
        res.send({ "message": `Added ${count} products` });
    }


})

app.get('/store-product-data', async (req, res) => {
    const bearerToken = await storage.getItem('token');
    // console.log(bearerToken);
    if (!bearerToken) {
        res.send('Not logged in');
    } else {

        const productList = await storage.getItem('product_list');
        let count = 0;
        if (Array.isArray(productList)) {
            await Promise.all(
                productList.map(async (product) => {

                    const endpoint = `${baseUrl}/rest/v3/catalog/products/${product.sku}`;
                    const signature = generateSignature('get', endpoint, null);
                    const dateAtClient = new Date().toISOString();

                    let responseText;
                    try {
                        const response = await axios.get(endpoint, {
                            headers: {
                                'Content-Type': 'application/json',
                                'dateAtClient': dateAtClient,
                                'signature': signature,
                                'Authorization': `Bearer ${bearerToken}`

                            }
                        });
                        responseText = response?.data;
                    } catch (error) {
                        console.error('Error getting bearer token:', error.message);
                        responseText = error;
                    }
                    if (!responseText?.message) {
                        await storage.setItem(product.sku, responseText);
                        count += 1;
                    }


                })
            )
        }
        res.send({ "message": `Added ${count} products` });
    }


})

app.get('/get-categories', async (req, res) => {

    const categoryList = await storage.getItem("category_list");

    res.send(categoryList);


})

app.get('/get-product-list', async (req, res) => {

    const productList = await storage.getItem("product_list");

    res.send(productList);


})

app.get('/get-product/:sku', async (req, res) => {

    const sku = req.params.sku;
    const product = await storage.getItem(sku);
    res.send(product);


})

app.listen(port, () => {
    console.log(`App listening on port ${port}`)
})
