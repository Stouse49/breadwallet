//
//  BRPeerManager.m
//  BreadWallet
//
//  Created by Aaron Voisine on 10/6/13.
//  Copyright (c) 2013 Aaron Voisine <voisine@gmail.com>
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

#import "BRPeerManager.h"
#import "BRPeer.h"
#import "BRPeerEntity.h"
#import "BRBloomFilter.h"
#import "BRKeySequence.h"
#import "BRTransaction.h"
#import "BRTransactionEntity.h"
#import "BRMerkleBlock.h"
#import "BRMerkleBlockEntity.h"
#import "BRWalletManager.h"
#import "NSString+Bitcoin.h"
#import "NSData+Bitcoin.h"
#import "NSManagedObject+Sugar.h"
#import "BREventManager.h"
#import "breadwallet-Swift.h"
#import <netdb.h>
#include <stdlib.h>

#if ! PEER_LOGGING
#define NSLog(...)
#endif

#define FIXED_PEERS          @"FixedPeers"
#define PROTOCOL_TIMEOUT     20.0
#define MAX_CONNECT_FAILURES 20 // notify user of network problems after this many connect failures in a row
#define CHECKPOINT_COUNT     (sizeof(checkpoint_array)/sizeof(*checkpoint_array))
#define GENESIS_BLOCK_HASH   (*(UInt256 *)@(checkpoint_array[0].hash).hexToData.reverse.bytes)
#define SYNC_STARTHEIGHT_KEY @"SYNC_STARTHEIGHT"

#if BITCOIN_TESTNET

static const struct { uint32_t height; const char *hash; uint32_t timestamp; uint32_t target; } checkpoint_array[] = {
    {      0, "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943", 1296688602, 0x1d00ffff },
    {  20160, "000000001cf5440e7c9ae69f655759b17a32aad141896defd55bb895b7cfc44e", 1345001466, 0x1c4d1756 },
    {  40320, "000000008011f56b8c92ff27fb502df5723171c5374673670ef0eee3696aee6d", 1355980158, 0x1d00ffff },
    {  60480, "00000000130f90cda6a43048a58788c0a5c75fa3c32d38f788458eb8f6952cee", 1363746033, 0x1c1eca8a },
    {  80640, "00000000002d0a8b51a9c028918db3068f976e3373d586f08201a4449619731c", 1369042673, 0x1c011c48 },
    { 100800, "0000000000a33112f86f3f7b0aa590cb4949b84c2d9c673e9e303257b3be9000", 1376543922, 0x1c00d907 },
    { 120960, "00000000003367e56e7f08fdd13b85bbb31c5bace2f8ca2b0000904d84960d0c", 1382025703, 0x1c00df4c },
    { 141120, "0000000007da2f551c3acd00e34cc389a4c6b6b3fad0e4e67907ad4c7ed6ab9f", 1384495076, 0x1c0ffff0 },
    { 161280, "0000000001d1b79a1aec5702aaa39bad593980dfe26799697085206ef9513486", 1388980370, 0x1c03fffc },
    { 181440, "00000000002bb4563a0ec21dc4136b37dcd1b9d577a75a695c8dd0b861e1307e", 1392304311, 0x1b336ce6 },
    { 201600, "0000000000376bb71314321c45de3015fe958543afcbada242a3b1b072498e38", 1393813869, 0x1b602ac0 }
};

static const char *dns_seeds[] = {
    "testnet-seed.breadwallet.com.", "testnet-seed.bitcoin.petertodd.org.", "testnet-seed.bluematt.me.",
    "testnet-seed.bitcoin.schildbach.de."
};

#else // main net

// blockchain checkpoints - these are also used as starting points for partial chain downloads, so they need to be at
// difficulty transition boundaries in order to verify the block difficulty at the immediately following transition
static const struct { uint32_t height; const char *hash; uint32_t timestamp; uint32_t target; } checkpoint_array[] = {
    {      0, "dced3542896ed537cb06f9cb064319adb0da615f64dd8c5e5bad974398f44b24", 1368560876, 0x1e0ffff0 },
    {  20160, "e19b119f4a633d89320d502e7c05b88d083acdff3b4bd40efcdca54b25f6cb2c", 1369548217, 0x1c22de48 },
    { 201600, "587ebf9221782de5e5669317f863cb56391c463195dca97e19d4e8ea6c71bd19", 1410984358, 0x1c046923 },
    { 443520, "d462b7f5888a4588d630c99a9c261e7ccc54f402b142ce1c4d51b5cb26358363", 1467199941, 0x1c1b8327 },
    { 564000, "9d67ce445d6b513074ef061066bb331871901b953b3bdeaa4dc0a4043cf189f8", 1485839612, 0x1c0c6b9e },
    { 690000, "93c7b08b99b3838110e538766a166f27607f2d5fda7ee0c7745525db7cfcea4f", 1504615272, 0x1c021e2b }

};

static const char *dns_seeds[] = {
    //"dnsseed.gldcoin.com", "seed.gldcoin.com", "vps.gldcoin.com"
    "168.235.108.149"
};

#endif

@interface BRPeerManager ()

@property (nonatomic, strong) NSMutableOrderedSet *peers;
@property (nonatomic, strong) NSMutableSet *connectedPeers, *misbehavinPeers, *nonFpTx;
@property (nonatomic, strong) BRPeer *downloadPeer, *fixedPeer;
@property (nonatomic, assign) uint32_t syncStartHeight, filterUpdateHeight;
@property (nonatomic, strong) BRBloomFilter *bloomFilter;
@property (nonatomic, assign) double fpRate;
@property (nonatomic, assign) NSUInteger taskId, connectFailures, misbehavinCount, maxConnectCount;
@property (nonatomic, assign) NSTimeInterval earliestKeyTime, lastRelayTime;
@property (nonatomic, strong) NSMutableDictionary *blocks, *orphans, *checkpoints, *txRelays, *txRequests;
@property (nonatomic, strong) NSMutableDictionary *publishedTx, *publishedCallback;
@property (nonatomic, strong) BRMerkleBlock *lastBlock, *lastOrphan;
@property (nonatomic, strong) dispatch_queue_t q;
@property (nonatomic, strong) id backgroundObserver, seedObserver;

@end

@implementation BRPeerManager

+ (instancetype)sharedInstance
{
    static id singleton = nil;
    static dispatch_once_t onceToken = 0;
    
    dispatch_once(&onceToken, ^{
        singleton = [self new];
    });
    
    return singleton;
}

- (instancetype)init
{
    if (! (self = [super init])) return nil;

    self.earliestKeyTime = [BRWalletManager sharedInstance].seedCreationTime;
    self.connectedPeers = [NSMutableSet set];
    self.misbehavinPeers = [NSMutableSet set];
    self.nonFpTx = [NSMutableSet set];
    self.taskId = UIBackgroundTaskInvalid;
    self.q = dispatch_queue_create("peermanager", NULL);
    self.orphans = [NSMutableDictionary dictionary];
    self.txRelays = [NSMutableDictionary dictionary];
    self.txRequests = [NSMutableDictionary dictionary];
    self.publishedTx = [NSMutableDictionary dictionary];
    self.publishedCallback = [NSMutableDictionary dictionary];
    self.maxConnectCount = PEER_MAX_CONNECTIONS;
    
    self.backgroundObserver =
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidEnterBackgroundNotification object:nil
        queue:nil usingBlock:^(NSNotification *note) {
            [self savePeers];
            [self saveBlocks];

            if (self.taskId == UIBackgroundTaskInvalid) {
                self.misbehavinCount = 0;
                [self.connectedPeers makeObjectsPerformSelector:@selector(disconnect)];
            }
        }];

    self.seedObserver =
        [[NSNotificationCenter defaultCenter] addObserverForName:BRWalletManagerSeedChangedNotification object:nil
        queue:nil usingBlock:^(NSNotification *note) {
            self.earliestKeyTime = [BRWalletManager sharedInstance].seedCreationTime;
            self.syncStartHeight = 0;
            [[NSUserDefaults standardUserDefaults] setInteger:0 forKey:SYNC_STARTHEIGHT_KEY];
            [self.txRelays removeAllObjects];
            [self.publishedTx removeAllObjects];
            [self.publishedCallback removeAllObjects];
            [BRMerkleBlockEntity deleteObjects:[BRMerkleBlockEntity allObjects]];
            [BRMerkleBlockEntity saveContext];
            _blocks = nil;
            _bloomFilter = nil;
            _lastBlock = nil;
            [[self.connectedPeers copy] makeObjectsPerformSelector:@selector(disconnect)];
        }];

    return self;
}

- (void)dealloc
{
    [NSObject cancelPreviousPerformRequestsWithTarget:self];
    if (self.backgroundObserver) [[NSNotificationCenter defaultCenter] removeObserver:self.backgroundObserver];
    if (self.seedObserver) [[NSNotificationCenter defaultCenter] removeObserver:self.seedObserver];
}

- (NSMutableOrderedSet *)peers
{
    if (_fixedPeer) return [NSMutableOrderedSet orderedSetWithObject:_fixedPeer];
    if (_peers.count >= _maxConnectCount) return _peers;

    @synchronized(self) {
        if (_peers.count >= _maxConnectCount) return _peers;
        _peers = [NSMutableOrderedSet orderedSet];

        [[BRPeerEntity context] performBlockAndWait:^{
            for (BRPeerEntity *e in [BRPeerEntity allObjects]) {
                @autoreleasepool {
                    if (e.misbehavin == 0) [_peers addObject:[e peer]];
                    else [self.misbehavinPeers addObject:[e peer]];
                }
            }
        }];

        [self sortPeers];

        // DNS peer discovery
        NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
        NSMutableArray *peers = [NSMutableArray arrayWithObject:[NSMutableArray array]];

        if (_peers.count < PEER_MAX_CONNECTIONS ||
            ((BRPeer *)_peers[PEER_MAX_CONNECTIONS - 1]).timestamp + 3*24*60*60 < now) {
            while (peers.count < sizeof(dns_seeds)/sizeof(*dns_seeds)) [peers addObject:[NSMutableArray array]];
        }
        
        if (peers.count > 0) {
            dispatch_apply(peers.count, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^(size_t i) {
                NSString *servname = @(BITCOIN_STANDARD_PORT).stringValue;
                struct addrinfo hints = { 0, AF_UNSPEC, SOCK_STREAM, 0, 0, 0, NULL, NULL }, *servinfo, *p;
                UInt128 addr = { .u32 = { 0, 0, CFSwapInt32HostToBig(0xffff), 0 } };

                NSLog(@"DNS lookup %s", dns_seeds[i]);
                
                if (getaddrinfo(dns_seeds[i], servname.UTF8String, &hints, &servinfo) == 0) {
                    for (p = servinfo; p != NULL; p = p->ai_next) {
                        if (p->ai_family == AF_INET) {
                            addr.u64[0] = 0;
                            addr.u32[2] = CFSwapInt32HostToBig(0xffff);
                            addr.u32[3] = ((struct sockaddr_in *)p->ai_addr)->sin_addr.s_addr;
                        }
//                        else if (p->ai_family == AF_INET6) {
//                            addr = *(UInt128 *)&((struct sockaddr_in6 *)p->ai_addr)->sin6_addr;
//                        }
                        else continue;
                        
                        uint16_t port = CFSwapInt16BigToHost(((struct sockaddr_in *)p->ai_addr)->sin_port);
                        NSTimeInterval age = 3*24*60*60 + arc4random_uniform(4*24*60*60); // add between 3 and 7 days
                    
                        [peers[i] addObject:[[BRPeer alloc] initWithAddress:addr port:port
                                             timestamp:(i > 0 ? now - age : now)
                                             services:SERVICES_NODE_NETWORK | SERVICES_NODE_BLOOM]];
                    }

                    freeaddrinfo(servinfo);
                }
            });
                        
            for (NSArray *a in peers) [_peers addObjectsFromArray:a];

#if BITCOIN_TESTNET
            [self sortPeers];
            return _peers;
#endif
            // if DNS peer discovery fails, fall back on a hard coded list of peers (list taken from satoshi client)
            /*if (_peers.count < PEER_MAX_CONNECTIONS) {
                UInt128 addr = { .u32 = { 0, 0, CFSwapInt32HostToBig(0xffff), 0 } };
            
                for (NSNumber *address in [NSArray arrayWithContentsOfFile:[[NSBundle mainBundle]
                                           pathForResource:FIXED_PEERS ofType:@"plist"]]) {
                    // give hard coded peers a timestamp between 7 and 14 days ago
                    addr.u32[3] = CFSwapInt32HostToBig(address.unsignedIntValue);
                    [_peers addObject:[[BRPeer alloc] initWithAddress:addr port:BITCOIN_STANDARD_PORT
                     timestamp:now - (7*24*60*60 + arc4random_uniform(7*24*60*60))
                     services:SERVICES_NODE_NETWORK | SERVICES_NODE_BLOOM]];
                }
            }*/
            
            [self sortPeers];
        }

        return _peers;
    }
}

- (NSMutableDictionary *)blocks
{
    if (_blocks.count > 0) return _blocks;

    [[BRMerkleBlockEntity context] performBlockAndWait:^{
        if (_blocks.count > 0) return;
        _blocks = [NSMutableDictionary dictionary];
        self.checkpoints = [NSMutableDictionary dictionary];

        for (int i = 0; i < CHECKPOINT_COUNT; i++) { // add checkpoints to the block collection
            UInt256 hash = *(UInt256 *)@(checkpoint_array[i].hash).hexToData.reverse.bytes;

            _blocks[uint256_obj(hash)] = [[BRMerkleBlock alloc] initWithBlockHash:hash version:1 prevBlock:UINT256_ZERO
                                          merkleRoot:UINT256_ZERO timestamp:checkpoint_array[i].timestamp
                                          target:checkpoint_array[i].target nonce:0 totalTransactions:0 hashes:nil
                                          flags:nil height:checkpoint_array[i].height];
            self.checkpoints[@(checkpoint_array[i].height)] = uint256_obj(hash);
        }

        for (BRMerkleBlockEntity *e in [BRMerkleBlockEntity allObjects]) {
            @autoreleasepool {
                BRMerkleBlock *b = e.merkleBlock;

                if (b) _blocks[uint256_obj(b.blockHash)] = b;
            }
        };
    }];

    return _blocks;
}

// this is used as part of a getblocks or getheaders request
- (NSArray *)blockLocatorArray
{
    // append 10 most recent block hashes, decending, then continue appending, doubling the step back each time,
    // finishing with the genesis block (top, -1, -2, -3, -4, -5, -6, -7, -8, -9, -11, -15, -23, -39, -71, -135, ..., 0)
    NSMutableArray *locators = [NSMutableArray array];
    int32_t step = 1, start = 0;
    BRMerkleBlock *b = self.lastBlock;

    while (b && b.height > 0) {
        [locators addObject:uint256_obj(b.blockHash)];
        if (++start >= 10) step *= 2;

        for (int32_t i = 0; b && i < step; i++) {
            b = self.blocks[uint256_obj(b.prevBlock)];
        }
    }

    [locators addObject:uint256_obj(GENESIS_BLOCK_HASH)];
    return locators;
}

- (BRMerkleBlock *)lastBlock
{
    if (! _lastBlock) {
        NSFetchRequest *req = [BRMerkleBlockEntity fetchReq];

        req.sortDescriptors = @[[NSSortDescriptor sortDescriptorWithKey:@"height" ascending:NO]];
        req.predicate = [NSPredicate predicateWithFormat:@"height >= 0 && height != %d", BLOCK_UNKNOWN_HEIGHT];
        req.fetchLimit = 1;
        _lastBlock = [[BRMerkleBlockEntity fetchObjects:req].lastObject merkleBlock];
        
        // if we don't have any blocks yet, use the latest checkpoint that's at least a week older than earliestKeyTime
        for (int i = CHECKPOINT_COUNT - 1; ! _lastBlock && i >= 0; i--) {
            if (i == 0 || checkpoint_array[i].timestamp + 7*24*60*60 < self.earliestKeyTime + NSTimeIntervalSince1970) {
                UInt256 hash = *(UInt256 *)@(checkpoint_array[i].hash).hexToData.reverse.bytes;
                
                _lastBlock = [[BRMerkleBlock alloc] initWithBlockHash:hash version:1 prevBlock:UINT256_ZERO
                              merkleRoot:UINT256_ZERO timestamp:checkpoint_array[i].timestamp
                              target:checkpoint_array[i].target nonce:0 totalTransactions:0 hashes:nil flags:nil
                              height:checkpoint_array[i].height];
            }
        }
        
        if (_lastBlock.height > _estimatedBlockHeight) _estimatedBlockHeight = _lastBlock.height;
    }
    
    return _lastBlock;
}

- (uint32_t)lastBlockHeight
{
    return self.lastBlock.height;
}

- (double)syncProgress
{
    if (! self.downloadPeer && self.syncStartHeight == 0) return 0.0;
    if (self.downloadPeer.status != BRPeerStatusConnected) return 0.05;
    if (self.lastBlockHeight >= self.estimatedBlockHeight) return 1.0;
    return 0.1 + 0.9*(self.lastBlockHeight - self.syncStartHeight)/(self.estimatedBlockHeight - self.syncStartHeight);
}

// number of connected peers
- (NSUInteger)peerCount
{
    NSUInteger count = 0;

    for (BRPeer *peer in [self.connectedPeers copy]) {
        if (peer.status == BRPeerStatusConnected) count++;
    }

    return count;
}

- (NSString *)downloadPeerName
{
    return [self.downloadPeer.host stringByAppendingFormat:@":%d", self.downloadPeer.port];
}

- (BRBloomFilter *)bloomFilterForPeer:(BRPeer *)peer
{
    BRWalletManager *manager = [BRWalletManager sharedInstance];
    
    // every time a new wallet address is added, the bloom filter has to be rebuilt, and each address is only used for
    // one transaction, so here we generate some spare addresses to avoid rebuilding the filter each time a wallet
    // transaction is encountered during the blockchain download
    [manager.wallet addressesWithGapLimit:SEQUENCE_GAP_LIMIT_EXTERNAL + 100 internal:NO];
    [manager.wallet addressesWithGapLimit:SEQUENCE_GAP_LIMIT_INTERNAL + 100 internal:YES];

    [self.orphans removeAllObjects]; // clear out orphans that may have been received on an old filter
    self.lastOrphan = nil;
    self.filterUpdateHeight = self.lastBlockHeight;
    self.fpRate = BLOOM_REDUCED_FALSEPOSITIVE_RATE;

    BRUTXO o;
    NSData *d;
    NSSet *addresses = [manager.wallet.allReceiveAddresses setByAddingObjectsFromSet:manager.wallet.allChangeAddresses];
    NSUInteger i, elemCount = addresses.count + manager.wallet.unspentOutputs.count;
    NSMutableArray *inputs = [NSMutableArray new];

    for (BRTransaction *tx in manager.wallet.allTransactions) { // find TXOs spent within the last 100 blocks
        [self addTransactionToPublishList:tx]; // also populate the tx publish list
        if (tx.blockHeight != TX_UNCONFIRMED && tx.blockHeight + 100 < self.lastBlockHeight) break;
        i = 0;
        
        for (NSValue *hash in tx.inputHashes) {
            [hash getValue:&o.hash];
            o.n = [tx.inputIndexes[i++] unsignedIntValue];
            
            BRTransaction *t = [manager.wallet transactionForHash:o.hash];
            
            if (o.n < t.outputAddresses.count && [manager.wallet containsAddress:t.outputAddresses[o.n]]) {
                [inputs addObject:brutxo_data(o)];
                elemCount++;
            }
        }
    }
    
    BRBloomFilter *filter = [[BRBloomFilter alloc] initWithFalsePositiveRate:self.fpRate
                             forElementCount:(elemCount < 200 ? 300 : elemCount + 100) tweak:(uint32_t)peer.hash
                             flags:BLOOM_UPDATE_ALL];

    for (NSString *addr in addresses) {// add addresses to watch for tx receiveing money to the wallet
        NSData *hash = addr.addressToHash160;

        if (hash && ! [filter containsData:hash]) [filter insertData:hash];
    }

    for (NSValue *utxo in manager.wallet.unspentOutputs) { // add UTXOs to watch for tx sending money from the wallet
        [utxo getValue:&o];
        d = brutxo_data(o);
        if (! [filter containsData:d]) [filter insertData:d];
    }
    
    for (d in inputs) { // also add TXOs spent within the last 100 blocks
        if (! [filter containsData:d]) [filter insertData:d];
    }
    
    // TODO: XXXX if already synced, recursively add inputs of unconfirmed receives
    _bloomFilter = filter;
    return _bloomFilter;
}

- (void)connect
{
    NSUserDefaults *defs = [NSUserDefaults standardUserDefaults];
    
    dispatch_async(self.q, ^{
        if ([BRWalletManager sharedInstance].noWallet) return; // check to make sure the wallet has been created
        if (self.connectFailures >= MAX_CONNECT_FAILURES) self.connectFailures = 0; // this attempt is a manual retry
    
        if (self.syncProgress < 1.0) {
            if (self.syncStartHeight == 0) self.syncStartHeight = (uint32_t)[defs integerForKey:SYNC_STARTHEIGHT_KEY];
            
            if (self.syncStartHeight == 0) {
                self.syncStartHeight = self.lastBlockHeight;
                [[NSUserDefaults standardUserDefaults] setInteger:self.syncStartHeight forKey:SYNC_STARTHEIGHT_KEY];
            }

            if (self.taskId == UIBackgroundTaskInvalid) { // start a background task for the chain sync
                self.taskId =
                    [[UIApplication sharedApplication] beginBackgroundTaskWithExpirationHandler:^{
                        dispatch_async(self.q, ^{
                            [self saveBlocks];
                        });

                        [self syncStopped];
                    }];
            }

            dispatch_async(dispatch_get_main_queue(), ^{
                [[NSNotificationCenter defaultCenter] postNotificationName:BRPeerManagerSyncStartedNotification
                 object:nil];
            });
        }

        [self.connectedPeers minusSet:[self.connectedPeers objectsPassingTest:^BOOL(id obj, BOOL *stop) {
            return ([obj status] == BRPeerStatusDisconnected) ? YES : NO;
        }]];
        
        self.fixedPeer = [BRPeer peerWithHost:[defs stringForKey:SETTINGS_FIXED_PEER_KEY]];
        self.maxConnectCount = (self.fixedPeer) ? 1 : PEER_MAX_CONNECTIONS;
        if (self.connectedPeers.count >= self.maxConnectCount) return; // already connected to maxConnectCount peers

        NSMutableOrderedSet *peers = [NSMutableOrderedSet orderedSetWithOrderedSet:self.peers];

        if (peers.count > 100) [peers removeObjectsInRange:NSMakeRange(100, peers.count - 100)];

        while (peers.count > 0 && self.connectedPeers.count < self.maxConnectCount) {
            // pick a random peer biased towards peers with more recent timestamps
            BRPeer *p = peers[(NSUInteger)(pow(arc4random_uniform((uint32_t)peers.count), 2)/peers.count)];

            if (p && ! [self.connectedPeers containsObject:p]) {
                [p setDelegate:self queue:self.q];
                p.earliestKeyTime = self.earliestKeyTime;
                [self.connectedPeers addObject:p];
                [p connect];
            }

            [peers removeObject:p];
        }

        if (self.connectedPeers.count == 0) {
            [self syncStopped];

            dispatch_async(dispatch_get_main_queue(), ^{
                NSError *error = [NSError errorWithDomain:@"BreadWallet" code:1
                                  userInfo:@{NSLocalizedDescriptionKey:NSLocalizedString(@"no peers found", nil)}];

                [[NSNotificationCenter defaultCenter] postNotificationName:BRPeerManagerSyncFailedNotification
                 object:nil userInfo:@{@"error":error}];
            });
        }
    });
}

- (void)disconnect
{
    for (BRPeer *peer in self.connectedPeers) {
        self.connectFailures = MAX_CONNECT_FAILURES; // prevent futher automatic reconnect attempts
        [peer disconnect];
    }
}

// rescans blocks and transactions after earliestKeyTime, a new random download peer is also selected due to the
// possibility that a malicious node might lie by omitting transactions that match the bloom filter
- (void)rescan
{
    if (! self.connected) return;

    dispatch_async(self.q, ^{
        _lastBlock = nil;

        // start the chain download from the most recent checkpoint that's at least a week older than earliestKeyTime
        for (int i = CHECKPOINT_COUNT - 1; ! _lastBlock && i >= 0; i--) {
            if (i == 0 || checkpoint_array[i].timestamp + 7*24*60*60 < self.earliestKeyTime + NSTimeIntervalSince1970) {
                UInt256 hash = *(UInt256 *)@(checkpoint_array[i].hash).hexToData.reverse.bytes;

                _lastBlock = self.blocks[uint256_obj(hash)];
            }
        }

        if (self.downloadPeer) { // disconnect the current download peer so a new random one will be selected
            [self.peers removeObject:self.downloadPeer];
            [self.downloadPeer disconnect];
        }

        self.syncStartHeight = self.lastBlockHeight;
        [[NSUserDefaults standardUserDefaults] setInteger:self.syncStartHeight forKey:SYNC_STARTHEIGHT_KEY];
        [self connect];
    });
}

// adds transaction to list of tx to be published, along with any unconfirmed inputs
- (void)addTransactionToPublishList:(BRTransaction *)transaction
{
    if (transaction.blockHeight == TX_UNCONFIRMED) {
        NSLog(@"[BRPeerManager] add transaction to publish list %@", transaction);
        self.publishedTx[uint256_obj(transaction.txHash)] = transaction;
    
        for (NSValue *hash in transaction.inputHashes) {
            UInt256 h = UINT256_ZERO;
            
            [hash getValue:&h];
            [self addTransactionToPublishList:[[BRWalletManager sharedInstance].wallet transactionForHash:h]];
        }
    }
}

- (void)publishTransaction:(BRTransaction *)transaction completion:(void (^)(NSError *error))completion
{
    NSLog(@"[BRPeerManager] publish transaction %@", transaction);
    if (! transaction.isSigned) {
        if (completion) {
            [[BREventManager sharedEventManager] saveEvent:@"peer_manager:not_signed"];
            completion([NSError errorWithDomain:@"BreadWallet" code:401 userInfo:@{NSLocalizedDescriptionKey:
                        NSLocalizedString(@"goldcoin transaction not signed", nil)}]);
        }
        
        return;
    }
    else if (! self.connected && self.connectFailures >= MAX_CONNECT_FAILURES) {
        if (completion) {
            [[BREventManager sharedEventManager] saveEvent:@"peer_manager:not_connected"];
            completion([NSError errorWithDomain:@"BreadWallet" code:-1009 userInfo:@{NSLocalizedDescriptionKey:
                        NSLocalizedString(@"not connected to the goldcoin network", nil)}]);
        }
        
        return;
    }

    NSMutableSet *peers = [NSMutableSet setWithSet:self.connectedPeers];
    NSValue *hash = uint256_obj(transaction.txHash);
    
    [self addTransactionToPublishList:transaction];
    if (completion) self.publishedCallback[hash] = completion;

    NSArray *txHashes = self.publishedTx.allKeys;

    // instead of publishing to all peers, leave out the download peer to see if the tx propogates and gets relayed back
    // TODO: XXX connect to a random peer with an empty or fake bloom filter just for publishing
    if (self.peerCount > 1 && self.downloadPeer) [peers removeObject:self.downloadPeer];

    dispatch_async(dispatch_get_main_queue(), ^{
        [self performSelector:@selector(txTimeout:) withObject:hash afterDelay:PROTOCOL_TIMEOUT];

        for (BRPeer *p in peers) {
            if (p.status != BRPeerStatusConnected) continue;
            [p sendInvMessageWithTxHashes:txHashes];
            [p sendPingMessageWithPongHandler:^(BOOL success) {
                if (! success) return;

                for (NSValue *h in txHashes) {
                    if ([self.txRelays[h] containsObject:p] || [self.txRequests[h] containsObject:p]) continue;
                    if (! self.txRequests[h]) self.txRequests[h] = [NSMutableSet set];
                    [self.txRequests[h] addObject:p];
                    [p sendGetdataMessageWithTxHashes:@[h] andBlockHashes:nil];
                }
            }];
        }
    });
}

// number of connected peers that have relayed the transaction
- (NSUInteger)relayCountForTransaction:(UInt256)txHash
{
    return [self.txRelays[uint256_obj(txHash)] count];
}

// seconds since reference date, 00:00:00 01/01/01 GMT
// NOTE: this is only accurate for the last two weeks worth of blocks, other timestamps are estimated from checkpoints
- (NSTimeInterval)timestampForBlockHeight:(uint32_t)blockHeight
{
    if (blockHeight == TX_UNCONFIRMED) return (self.lastBlock.timestamp - NSTimeIntervalSince1970) + 10*60; //next block

    if (blockHeight >= self.lastBlockHeight) { // future block, assume 10 minutes per block after last block
        return (self.lastBlock.timestamp - NSTimeIntervalSince1970) + (blockHeight - self.lastBlockHeight)*10*60;
    }

    if (_blocks.count > 0) {
        if (blockHeight >= self.lastBlockHeight - BLOCK_DIFFICULTY_INTERVAL*2) { // recent block we have the header for
            BRMerkleBlock *block = self.lastBlock;

            while (block && block.height > blockHeight) block = self.blocks[uint256_obj(block.prevBlock)];
            if (block) return block.timestamp - NSTimeIntervalSince1970;
        }
    }
    else [[BRMerkleBlockEntity context] performBlock:^{ [self blocks]; }];

    uint32_t h = self.lastBlockHeight, t = self.lastBlock.timestamp;

    for (int i = CHECKPOINT_COUNT - 1; i >= 0; i--) { // estimate from checkpoints
        if (checkpoint_array[i].height <= blockHeight) {
            t = checkpoint_array[i].timestamp + (t - checkpoint_array[i].timestamp)*
                (blockHeight - checkpoint_array[i].height)/(h - checkpoint_array[i].height);
            return t - NSTimeIntervalSince1970;
        }

        h = checkpoint_array[i].height;
        t = checkpoint_array[i].timestamp;
    }

    return checkpoint_array[0].timestamp - NSTimeIntervalSince1970;
}

- (void)setBlockHeight:(int32_t)height andTimestamp:(NSTimeInterval)timestamp forTxHashes:(NSArray *)txHashes
{
    NSArray *updatedTx = [[BRWalletManager sharedInstance].wallet setBlockHeight:height andTimestamp:timestamp
                          forTxHashes:txHashes];
    
    if (height != TX_UNCONFIRMED) { // remove confirmed tx from publish list and relay counts
        [self.publishedTx removeObjectsForKeys:txHashes];
        [self.publishedCallback removeObjectsForKeys:txHashes];
        [self.txRelays removeObjectsForKeys:txHashes];
    }
    
    for (NSValue *hash in updatedTx) {
        NSError *kvErr = nil;
        BRTxMetadataObject *txm;
        UInt256 h;
        
        [hash getValue:&h];
        txm = [[BRTxMetadataObject alloc] initWithTxHash:h store:[BRAPIClient sharedClient].kv];
        txm.blockHeight = height;
        if (txm) [[BRAPIClient sharedClient].kv set:txm error:&kvErr];
    }
}

- (void)txTimeout:(NSValue *)txHash
{
    void (^callback)(NSError *error) = self.publishedCallback[txHash];

    [self.publishedTx removeObjectForKey:txHash];
    [self.publishedCallback removeObjectForKey:txHash];
    [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(txTimeout:) object:txHash];

    if (callback) {
        [[BREventManager sharedEventManager] saveEvent:@"peer_manager:tx_canceled_timeout"];
        callback([NSError errorWithDomain:@"BreadWallet" code:BITCOIN_TIMEOUT_CODE userInfo:@{NSLocalizedDescriptionKey:
                  NSLocalizedString(@"transaction canceled, network timeout", nil)}]);
    }
}

- (void)syncTimeout
{
    NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];

    if (now - self.lastRelayTime < PROTOCOL_TIMEOUT) { // the download peer relayed something in time, so restart timer
        [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(syncTimeout) object:nil];
        [self performSelector:@selector(syncTimeout) withObject:nil
         afterDelay:PROTOCOL_TIMEOUT - (now - self.lastRelayTime)];
        return;
    }

    dispatch_async(self.q, ^{
        if (! self.downloadPeer) return;
        NSLog(@"%@:%d chain sync timed out", self.downloadPeer.host, self.downloadPeer.port);
        [self.peers removeObject:self.downloadPeer];
        [self.downloadPeer disconnect];
    });
}

- (void)syncStopped
{
    dispatch_async(dispatch_get_main_queue(), ^{
        [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(syncTimeout) object:nil];

        if (self.taskId != UIBackgroundTaskInvalid) {
            [[UIApplication sharedApplication] endBackgroundTask:self.taskId];
            self.taskId = UIBackgroundTaskInvalid;
        }
    });
}

- (void)loadMempools
{
    for (BRPeer *p in self.connectedPeers) { // after syncing, load filters and get mempools from other peers
        if (p.status != BRPeerStatusConnected) continue;
        
        if (p != self.downloadPeer || self.fpRate > BLOOM_REDUCED_FALSEPOSITIVE_RATE*5.0) {
            [p sendFilterloadMessage:[self bloomFilterForPeer:p].data];
        }
        
        [p sendInvMessageWithTxHashes:self.publishedCallback.allKeys]; // publish pending tx
        [p sendPingMessageWithPongHandler:^(BOOL success) {
            if (success) {
                [p sendMempoolMessage:self.publishedTx.allKeys completion:^(BOOL success) {
                    if (success) {
                        p.synced = YES;
                        [self removeUnrelayedTransactions];
                        [p sendGetaddrMessage]; // request a list of other goldcoin peers
                        
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [[NSNotificationCenter defaultCenter]
                             postNotificationName:BRPeerManagerTxStatusNotification object:nil];
                        });
                    }
                    
                    if (p == self.downloadPeer) {
                        [self syncStopped];

                        dispatch_async(dispatch_get_main_queue(), ^{
                            [[NSNotificationCenter defaultCenter]
                             postNotificationName:BRPeerManagerSyncFinishedNotification object:nil];
                        });
                    }
                }];
            }
            else if (p == self.downloadPeer) {
                [self syncStopped];

                dispatch_async(dispatch_get_main_queue(), ^{
                    [[NSNotificationCenter defaultCenter]
                     postNotificationName:BRPeerManagerSyncFinishedNotification object:nil];
                });
            }
        }];
    }
}

// unconfirmed transactions that aren't in the mempools of any of connected peers have likely dropped off the network
- (void)removeUnrelayedTransactions
{
    BRWalletManager *manager = [BRWalletManager sharedInstance];
    BOOL rescan = NO, notify = NO;
    NSValue *hash;
    UInt256 h;

    // don't remove transactions until we're connected to maxConnectCount peers
    if (self.peerCount < self.maxConnectCount) return;
    
    for (BRPeer *p in self.connectedPeers) { // don't remove tx until all peers have finished relaying their mempools
        if (! p.synced) return;
    }

    for (BRTransaction *tx in manager.wallet.allTransactions) {
        if (tx.blockHeight != TX_UNCONFIRMED) break;
        hash = uint256_obj(tx.txHash);
        if (self.publishedCallback[hash] != NULL) continue;
        
        if ([self.txRelays[hash] count] == 0 && [self.txRequests[hash] count] == 0) {
            // if this is for a transaction we sent, and it wasn't already known to be invalid, notify user of failure
            if (! rescan && [manager.wallet amountSentByTransaction:tx] > 0 && [manager.wallet transactionIsValid:tx]) {
                NSLog(@"failed transaction %@", tx);
                rescan = notify = YES;
                
                for (NSValue *hash in tx.inputHashes) { // only recommend a rescan if all inputs are confirmed
                    [hash getValue:&h];
                    if ([manager.wallet transactionForHash:h].blockHeight != TX_UNCONFIRMED) continue;
                    rescan = NO;
                    break;
                }
            }
            
            [manager.wallet removeTransaction:tx.txHash];
        }
        else if ([self.txRelays[hash] count] < self.maxConnectCount) {
            // set timestamp 0 to mark as unverified
            [self setBlockHeight:TX_UNCONFIRMED andTimestamp:0 forTxHashes:@[hash]];
        }
    }
    
    if (notify) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (rescan) {
                [[BREventManager sharedEventManager] saveEvent:@"peer_manager:tx_rejected_rescan"];
                [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"transaction rejected", nil)
                  message:NSLocalizedString(@"Your wallet may be out of sync.\n"
                                            "This can often be fixed by rescanning the blockchain.", nil) delegate:self
                  cancelButtonTitle:NSLocalizedString(@"cancel", nil)
                  otherButtonTitles:NSLocalizedString(@"rescan", nil), nil] show];
            }
            else {
                [[BREventManager sharedEventManager] saveEvent:@"peer_manager_tx_rejected"];
                [[[UIAlertView alloc] initWithTitle:NSLocalizedString(@"transaction rejected", nil)
                  message:nil delegate:nil cancelButtonTitle:NSLocalizedString(@"ok", nil) otherButtonTitles:nil] show];
            }
        });
    }
}

- (void)updateFilter
{
    if (self.downloadPeer.needsFilterUpdate) return;
    self.downloadPeer.needsFilterUpdate = YES;
    NSLog(@"filter update needed, waiting for pong");
    
    [self.downloadPeer sendPingMessageWithPongHandler:^(BOOL success) { // wait for pong so we include already sent tx
        if (! success) return;
        NSLog(@"updating filter with newly created wallet addresses");
        _bloomFilter = nil;

        if (self.lastBlockHeight < self.estimatedBlockHeight) { // if we're syncing, only update download peer
            [self.downloadPeer sendFilterloadMessage:[self bloomFilterForPeer:self.downloadPeer].data];
            [self.downloadPeer sendPingMessageWithPongHandler:^(BOOL success) { // wait for pong so filter is loaded
                if (! success) return;
                self.downloadPeer.needsFilterUpdate = NO;
                [self.downloadPeer rerequestBlocksFrom:self.lastBlock.blockHash];
                [self.downloadPeer sendPingMessageWithPongHandler:^(BOOL success) {
                    if (! success || self.downloadPeer.needsFilterUpdate) return;
                    [self.downloadPeer sendGetblocksMessageWithLocators:[self blockLocatorArray]
                     andHashStop:UINT256_ZERO];
                }];
            }];
        }
        else {
            for (BRPeer *p in self.connectedPeers) {
                if (p.status != BRPeerStatusConnected) continue;
                [p sendFilterloadMessage:[self bloomFilterForPeer:p].data];
                [p sendPingMessageWithPongHandler:^(BOOL success) { // wait for pong so we know filter is loaded
                    if (! success) return;
                    p.needsFilterUpdate = NO;
                    [p sendMempoolMessage:self.publishedTx.allKeys completion:nil];
                }];
            }
        }
    }];
}

- (void)peerMisbehavin:(BRPeer *)peer
{
    peer.misbehavin++;
    [self.peers removeObject:peer];
    [self.misbehavinPeers addObject:peer];

    if (++self.misbehavinCount >= 10) { // clear out stored peers so we get a fresh list from DNS for next connect
        self.misbehavinCount = 0;
        [self.misbehavinPeers removeAllObjects];
        [BRPeerEntity deleteObjects:[BRPeerEntity allObjects]];
        _peers = nil;
    }
    
    [peer disconnect];
    [self connect];
}

- (void)sortPeers
{
    [_peers sortUsingComparator:^NSComparisonResult(BRPeer *p1, BRPeer *p2) {
        if (p1.timestamp > p2.timestamp) return NSOrderedAscending;
        if (p1.timestamp < p2.timestamp) return NSOrderedDescending;
        return NSOrderedSame;
    }];
}

- (void)savePeers
{
    NSLog(@"[BRPeerManager] save peers");
    NSMutableSet *peers = [[self.peers.set setByAddingObjectsFromSet:self.misbehavinPeers] mutableCopy];
    NSMutableSet *addrs = [NSMutableSet set];

    for (BRPeer *p in peers) {
        if (p.address.u64[0] != 0 || p.address.u32[2] != CFSwapInt32HostToBig(0xffff)) continue; // skip IPv6 for now
        [addrs addObject:@(CFSwapInt32BigToHost(p.address.u32[3]))];
    }

    [[BRPeerEntity context] performBlock:^{
        [BRPeerEntity deleteObjects:[BRPeerEntity objectsMatching:@"! (address in %@)", addrs]]; // remove deleted peers

        for (BRPeerEntity *e in [BRPeerEntity objectsMatching:@"address in %@", addrs]) { // update existing peers
            @autoreleasepool {
                BRPeer *p = [peers member:[e peer]];
                
                if (p) {
                    e.timestamp = p.timestamp;
                    e.services = p.services;
                    e.misbehavin = p.misbehavin;
                    [peers removeObject:p];
                }
                else [e deleteObject];
            }
        }

        for (BRPeer *p in peers) {
            @autoreleasepool {
                [[BRPeerEntity managedObject] setAttributesFromPeer:p]; // add new peers
            }
        }
    }];
}

- (void)saveBlocks
{
    NSLog(@"[BRPeerManager] save blocks");
    NSMutableDictionary *blocks = [NSMutableDictionary dictionary];
    BRMerkleBlock *b = self.lastBlock;

    while (b) {
        blocks[[NSData dataWithBytes:b.blockHash.u8 length:sizeof(UInt256)]] = b;
        b = self.blocks[uint256_obj(b.prevBlock)];
    }

    [[BRMerkleBlockEntity context] performBlock:^{
        [BRMerkleBlockEntity deleteObjects:[BRMerkleBlockEntity objectsMatching:@"! (blockHash in %@)",
                                            blocks.allKeys]];

        for (BRMerkleBlockEntity *e in [BRMerkleBlockEntity objectsMatching:@"blockHash in %@", blocks.allKeys]) {
            @autoreleasepool {
                [e setAttributesFromBlock:blocks[e.blockHash]];
                [blocks removeObjectForKey:e.blockHash];
            }
        }

        for (BRMerkleBlock *b in blocks.allValues) {
            @autoreleasepool {
                [[BRMerkleBlockEntity managedObject] setAttributesFromBlock:b];
            }
        }
        
        [BRMerkleBlockEntity saveContext];
    }];
}

// MARK: - BRPeerDelegate

- (void)peerConnected:(BRPeer *)peer
{
    NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
    
    if (peer.timestamp > now + 2*60*60 || peer.timestamp < now - 2*60*60) peer.timestamp = now; //timestamp sanity check
    self.connectFailures = 0;
    NSLog(@"%@:%d connected with lastblock %d", peer.host, peer.port, peer.lastblock);
    
    // drop peers that don't carry full blocks, or aren't synced yet
    // TODO: XXXX does this work with 0.11 pruned nodes?
    if (! (peer.services & SERVICES_NODE_NETWORK) || peer.lastblock + 10 < self.lastBlockHeight) {
        [peer disconnect];
        return;
    }

    // drop peers that don't support SPV filtering
    if (peer.version >= 70011 && ! (peer.services & SERVICES_NODE_BLOOM)) {
        [peer disconnect];
        return;
    }

    if (self.connected && (self.estimatedBlockHeight >= peer.lastblock || self.lastBlockHeight >= peer.lastblock)) {
        if (self.lastBlockHeight < self.estimatedBlockHeight) return; // don't load bloom filter yet if we're syncing
        [peer sendFilterloadMessage:[self bloomFilterForPeer:peer].data];
        [peer sendInvMessageWithTxHashes:self.publishedCallback.allKeys]; // publish pending tx
        [peer sendPingMessageWithPongHandler:^(BOOL success) {
            if (! success) return;
            [peer sendMempoolMessage:self.publishedTx.allKeys completion:^(BOOL success) {
                if (! success) return;
                peer.synced = YES;
                [self removeUnrelayedTransactions];
                [peer sendGetaddrMessage]; // request a list of other goldcoin peers
                
                dispatch_async(dispatch_get_main_queue(), ^{
                    [[NSNotificationCenter defaultCenter] postNotificationName:BRPeerManagerTxStatusNotification
                     object:nil];
                });
            }];
        }];

        return; // we're already connected to a download peer
    }

    // select the peer with the lowest ping time to download the chain from if we're behind
    // BUG: XXX a malicious peer can report a higher lastblock to make us select them as the download peer, if two
    // peers agree on lastblock, use one of them instead
    for (BRPeer *p in self.connectedPeers) {
        if (p.status != BRPeerStatusConnected) continue;
        if ((p.pingTime < peer.pingTime && p.lastblock >= peer.lastblock) || p.lastblock > peer.lastblock) peer = p;
    }

    [self.downloadPeer disconnect];
    self.downloadPeer = peer;
    _connected = YES;
    _estimatedBlockHeight = peer.lastblock;
    [peer sendFilterloadMessage:[self bloomFilterForPeer:peer].data];
    peer.currentBlockHeight = self.lastBlockHeight;
    
    if (self.lastBlockHeight < peer.lastblock) { // start blockchain sync
        self.lastRelayTime = 0;
        
        dispatch_async(dispatch_get_main_queue(), ^{ // setup a timer to detect if the sync stalls
            [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(syncTimeout) object:nil];
            [self performSelector:@selector(syncTimeout) withObject:nil afterDelay:PROTOCOL_TIMEOUT];

            [[NSNotificationCenter defaultCenter] postNotificationName:BRPeerManagerTxStatusNotification object:nil];
            
            dispatch_async(self.q, ^{
                // request just block headers up to a week before earliestKeyTime, and then merkleblocks after that
                // BUG: XXX headers can timeout on slow connections (each message is over 160k)
                if (self.lastBlock.timestamp + 7*24*60*60 >= self.earliestKeyTime + NSTimeIntervalSince1970) {
                    [peer sendGetblocksMessageWithLocators:[self blockLocatorArray] andHashStop:UINT256_ZERO];
                }
                else [peer sendGetheadersMessageWithLocators:[self blockLocatorArray] andHashStop:UINT256_ZERO];
            });
        });
    }
    else { // we're already synced
        self.syncStartHeight = 0;
        [[NSUserDefaults standardUserDefaults] setInteger:0 forKey:SYNC_STARTHEIGHT_KEY];
        [self loadMempools];
    }
}

- (void)peer:(BRPeer *)peer disconnectedWithError:(NSError *)error
{
    NSLog(@"%@:%d disconnected%@%@", peer.host, peer.port, (error ? @", " : @""), (error ? error : @""));
    
    if ([error.domain isEqual:@"BreadWallet"] && error.code != BITCOIN_TIMEOUT_CODE) {
        [self peerMisbehavin:peer]; // if it's protocol error other than timeout, the peer isn't following the rules
    }
    else if (error) { // timeout or some non-protocol related network error
        [self.peers removeObject:peer];
        self.connectFailures++;
    }

    for (NSValue *txHash in self.txRelays.allKeys) {
        [self.txRelays[txHash] removeObject:peer];
    }

    if ([self.downloadPeer isEqual:peer]) { // download peer disconnected
        _connected = NO;
        self.downloadPeer = nil;
        if (self.connectFailures > MAX_CONNECT_FAILURES) self.connectFailures = MAX_CONNECT_FAILURES;
    }

    if (! self.connected && self.connectFailures == MAX_CONNECT_FAILURES) {
        [self syncStopped];
        
        // clear out stored peers so we get a fresh list from DNS on next connect attempt
        [self.misbehavinPeers removeAllObjects];
        [BRPeerEntity deleteObjects:[BRPeerEntity allObjects]];
        _peers = nil;

        dispatch_async(dispatch_get_main_queue(), ^{
            [[NSNotificationCenter defaultCenter] postNotificationName:BRPeerManagerSyncFailedNotification
             object:nil userInfo:(error) ? @{@"error":error} : nil];
        });
    }
    else if (self.connectFailures < MAX_CONNECT_FAILURES && (self.taskId != UIBackgroundTaskInvalid ||
             [UIApplication sharedApplication].applicationState != UIApplicationStateBackground)) {
        [self connect]; // try connecting to another peer
    }
    
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] postNotificationName:BRPeerManagerTxStatusNotification object:nil];
    });
}

- (void)peer:(BRPeer *)peer relayedPeers:(NSArray *)peers
{
    NSLog(@"%@:%d relayed %d peer(s)", peer.host, peer.port, (int)peers.count);
    [self.peers addObjectsFromArray:peers];
    [self.peers minusSet:self.misbehavinPeers];
    [self sortPeers];

    // limit total to 2500 peers
    if (self.peers.count > 2500) [self.peers removeObjectsInRange:NSMakeRange(2500, self.peers.count - 2500)];

    NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];

    // remove peers more than 3 hours old, or until there are only 1000 left
    while (self.peers.count > 1000 && ((BRPeer *)self.peers.lastObject).timestamp + 3*60*60 < now) {
        [self.peers removeObject:self.peers.lastObject];
    }

    if (peers.count > 1 && peers.count < 1000) [self savePeers]; // peer relaying is complete when we receive <1000
}

- (void)peer:(BRPeer *)peer relayedTransaction:(BRTransaction *)transaction
{
    BRWalletManager *manager = [BRWalletManager sharedInstance];
    NSValue *hash = uint256_obj(transaction.txHash);
    BOOL syncing = (self.lastBlockHeight < self.estimatedBlockHeight);
    void (^callback)(NSError *error) = self.publishedCallback[hash];

    NSLog(@"%@:%d relayed transaction %@", peer.host, peer.port, hash);
    
    transaction.timestamp = [NSDate timeIntervalSinceReferenceDate];
    if (syncing && ! [manager.wallet containsTransaction:transaction]) return;
    if (! [manager.wallet registerTransaction:transaction]) return;
    if (peer == self.downloadPeer) self.lastRelayTime = [NSDate timeIntervalSinceReferenceDate];

    if ([manager.wallet amountSentByTransaction:transaction] > 0 && [manager.wallet transactionIsValid:transaction]) {
        [self addTransactionToPublishList:transaction]; // add valid send tx to mempool
    }
    
    // keep track of how many peers have or relay a tx, this indicates how likely the tx is to confirm
    if (callback || (! syncing && ! [self.txRelays[hash] containsObject:peer])) {
        if (! self.txRelays[hash]) self.txRelays[hash] = [NSMutableSet set];
        [self.txRelays[hash] addObject:peer];
        if (callback) [self.publishedCallback removeObjectForKey:hash];

        if ([self.txRelays[hash] count] >= self.maxConnectCount &&
            [manager.wallet transactionForHash:transaction.txHash].blockHeight == TX_UNCONFIRMED &&
            [manager.wallet transactionForHash:transaction.txHash].timestamp == 0) {
            [self setBlockHeight:TX_UNCONFIRMED andTimestamp:[NSDate timeIntervalSinceReferenceDate]
             forTxHashes:@[hash]]; // set timestamp when tx is verified
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            NSError *kvErr = nil;
            
            [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(txTimeout:) object:hash];
            [[NSNotificationCenter defaultCenter] postNotificationName:BRPeerManagerTxStatusNotification object:nil];
            if (callback) callback(nil);
            
            [[BRAPIClient sharedClient].kv
             set:[[BRTxMetadataObject alloc] initWithTransaction:transaction exchangeRate:manager.localCurrencyPrice
                  exchangeRateCurrency:manager.localCurrencyCode feeRate:manager.wallet.feePerKb
                  deviceId:[BRAPIClient sharedClient].deviceId] error:&kvErr];
        });
    }
    
    [self.nonFpTx addObject:hash];
    [self.txRequests[hash] removeObject:peer];
    if (! _bloomFilter) return; // bloom filter is aready being updated

    // the transaction likely consumed one or more wallet addresses, so check that at least the next <gap limit>
    // unused addresses are still matched by the bloom filter
    NSArray *external = [manager.wallet addressesWithGapLimit:SEQUENCE_GAP_LIMIT_EXTERNAL internal:NO],
            *internal = [manager.wallet addressesWithGapLimit:SEQUENCE_GAP_LIMIT_INTERNAL internal:YES];
    
    for (NSString *address in [external arrayByAddingObjectsFromArray:internal]) {
        NSData *hash = address.addressToHash160;

        if (! hash || [_bloomFilter containsData:hash]) continue;
        _bloomFilter = nil; // reset bloom filter so it's recreated with new wallet addresses
        [self updateFilter];
        break;
    }
}

- (void)peer:(BRPeer *)peer hasTransaction:(UInt256)txHash
{
    BRWalletManager *manager = [BRWalletManager sharedInstance];
    NSValue *hash = uint256_obj(txHash);
    BOOL syncing = (self.lastBlockHeight < self.estimatedBlockHeight);
    BRTransaction *tx = self.publishedTx[hash];
    void (^callback)(NSError *error) = self.publishedCallback[hash];
    
    NSLog(@"%@:%d has transaction %@", peer.host, peer.port, hash);
    if (! tx) tx = [manager.wallet transactionForHash:txHash];
    if (! tx || (syncing && ! [manager.wallet containsTransaction:tx])) return;
    if (! [manager.wallet registerTransaction:tx]) return;
    if (peer == self.downloadPeer) self.lastRelayTime = [NSDate timeIntervalSinceReferenceDate];
    
    // keep track of how many peers have or relay a tx, this indicates how likely the tx is to confirm
    if (callback || (! syncing && ! [self.txRelays[hash] containsObject:peer])) {
        if (! self.txRelays[hash]) self.txRelays[hash] = [NSMutableSet set];
        [self.txRelays[hash] addObject:peer];
        if (callback) [self.publishedCallback removeObjectForKey:hash];

        if ([self.txRelays[hash] count] >= self.maxConnectCount &&
            [manager.wallet transactionForHash:txHash].blockHeight == TX_UNCONFIRMED &&
            [manager.wallet transactionForHash:txHash].timestamp == 0) {
            [self setBlockHeight:TX_UNCONFIRMED andTimestamp:[NSDate timeIntervalSinceReferenceDate]
             forTxHashes:@[hash]]; // set timestamp when tx is verified
        }
        
        dispatch_async(dispatch_get_main_queue(), ^{
            NSError *kvErr = nil;
            
            [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(txTimeout:) object:hash];
            [[NSNotificationCenter defaultCenter] postNotificationName:BRPeerManagerTxStatusNotification object:nil];
            if (callback) callback(nil);

            [[BRAPIClient sharedClient].kv
             set:[[BRTxMetadataObject alloc] initWithTransaction:tx exchangeRate:manager.localCurrencyPrice
                  exchangeRateCurrency:manager.localCurrencyCode feeRate:manager.wallet.feePerKb
                  deviceId:[BRAPIClient sharedClient].deviceId] error:&kvErr];
        });
    }
    
    [self.nonFpTx addObject:hash];
    [self.txRequests[hash] removeObject:peer];
}

- (void)peer:(BRPeer *)peer rejectedTransaction:(UInt256)txHash withCode:(uint8_t)code
{
    BRWalletManager *manager = [BRWalletManager sharedInstance];
    BRTransaction *tx = [manager.wallet transactionForHash:txHash];
    NSValue *hash = uint256_obj(txHash);
    
    if ([self.txRelays[hash] containsObject:peer]) {
        [self.txRelays[hash] removeObject:peer];

        if (tx.blockHeight == TX_UNCONFIRMED) { // set timestamp 0 for unverified
            [self setBlockHeight:TX_UNCONFIRMED andTimestamp:0 forTxHashes:@[hash]];
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            [[NSNotificationCenter defaultCenter] postNotificationName:BRPeerManagerTxStatusNotification object:nil];
#if DEBUG
            [[[UIAlertView alloc] initWithTitle:@"transaction rejected"
              message:[NSString stringWithFormat:@"rejected by %@:%d with code 0x%x", peer.host, peer.port, code]
              delegate:nil cancelButtonTitle:@"ok" otherButtonTitles:nil] show];
#endif
        });
    }
    
    [self.txRequests[hash] removeObject:peer];
    
    // if we get rejected for any reason other than double-spend, the peer is likely misconfigured
    if (code != REJECT_SPENT && [manager.wallet amountSentByTransaction:tx] > 0) {
        for (hash in tx.inputHashes) { // check that all inputs are confirmed before dropping peer
            UInt256 h = UINT256_ZERO;
            
            [hash getValue:&h];
            if ([manager.wallet transactionForHash:h].blockHeight == TX_UNCONFIRMED) return;
        }

        [self peerMisbehavin:peer];
    }
}

- (void)peer:(BRPeer *)peer relayedBlock:(BRMerkleBlock *)block
{
    // ignore block headers that are newer than one week before earliestKeyTime (headers have 0 totalTransactions)
    if (block.totalTransactions == 0 &&
        block.timestamp + 7*24*60*60 > self.earliestKeyTime + NSTimeIntervalSince1970 + 2*60*60) return;

    NSArray *txHashes = block.txHashes;

    // track the observed bloom filter false positive rate using a low pass filter to smooth out variance
    if (peer == self.downloadPeer && block.totalTransactions > 0) {
        NSMutableSet *fp = [NSMutableSet setWithArray:txHashes];
    
        // 1% low pass filter, also weights each block by total transactions, using 1400 tx per block as typical
        [fp minusSet:self.nonFpTx]; // wallet tx are not false-positives
        [self.nonFpTx removeAllObjects];
        self.fpRate = self.fpRate*(1.0 - 0.01*block.totalTransactions/1400) + 0.01*fp.count/1400;

        // false positive rate sanity check
        if (self.downloadPeer.status == BRPeerStatusConnected && self.fpRate > BLOOM_DEFAULT_FALSEPOSITIVE_RATE*10.0) {
            NSLog(@"%@:%d bloom filter false positive rate %f too high after %d blocks, disconnecting...", peer.host,
                  peer.port, self.fpRate, self.lastBlockHeight + 1 - self.filterUpdateHeight);
            [self.downloadPeer disconnect];
        }
        else if (self.lastBlockHeight + 500 < peer.lastblock && self.fpRate > BLOOM_REDUCED_FALSEPOSITIVE_RATE*10.0) {
            [self updateFilter]; // rebuild bloom filter when it starts to degrade
        }
    }

    if (! _bloomFilter) { // ingore potentially incomplete blocks when a filter update is pending
        if (peer == self.downloadPeer) self.lastRelayTime = [NSDate timeIntervalSinceReferenceDate];
        return;
    }

    NSValue *blockHash = uint256_obj(block.blockHash), *prevBlock = uint256_obj(block.prevBlock);
    BRMerkleBlock *prev = self.blocks[prevBlock];
    uint32_t transitionTime = 0, txTime = 0;
    UInt256 checkpoint = UINT256_ZERO;
    BOOL syncDone = NO;
    
    if (! prev) { // block is an orphan
        NSLog(@"%@:%d relayed orphan block %@, previous %@, last block is %@, height %d", peer.host, peer.port,
              blockHash, prevBlock, uint256_obj(self.lastBlock.blockHash), self.lastBlockHeight);

        // ignore orphans older than one week ago
        if (block.timestamp < [NSDate timeIntervalSinceReferenceDate] + NSTimeIntervalSince1970 - 7*24*60*60) return;

        // call getblocks, unless we already did with the previous block, or we're still downloading the chain
        if (self.lastBlockHeight >= peer.lastblock && ! uint256_eq(self.lastOrphan.blockHash, block.prevBlock)) {
            NSLog(@"%@:%d calling getblocks", peer.host, peer.port);
            [peer sendGetblocksMessageWithLocators:[self blockLocatorArray] andHashStop:UINT256_ZERO];
        }

        self.orphans[prevBlock] = block; // orphans are indexed by prevBlock instead of blockHash
        self.lastOrphan = block;
        return;
    }

    block.height = prev.height + 1;
    txTime = block.timestamp/2 + prev.timestamp/2;

    /*if ((block.height % BLOCK_DIFFICULTY_INTERVAL) == 0) { // hit a difficulty transition, find previous transition time
        BRMerkleBlock *b = block;

        for (uint32_t i = 0; b && i < BLOCK_DIFFICULTY_INTERVAL; i++) {
            b = self.blocks[uint256_obj(b.prevBlock)];
        }

        [[BRMerkleBlockEntity context] performBlock:^{ // save transition blocks to core data immediately
            @autoreleasepool {
                BRMerkleBlockEntity *e = [BRMerkleBlockEntity objectsMatching:@"blockHash == %@",
                                          [NSData dataWithBytes:b.blockHash.u8 length:sizeof(UInt256)]].lastObject;
        
                if (! e) e = [BRMerkleBlockEntity managedObject];
                [e setAttributesFromBlock:b];
            }
            
            [BRMerkleBlockEntity saveContext]; // persist core data to disk
        }];

        transitionTime = b.timestamp;
        
        while (b) { // free up some memory
            b = self.blocks[uint256_obj(b.prevBlock)];

            if (b && (b.height % BLOCK_DIFFICULTY_INTERVAL) != 0) {
                [self.blocks removeObjectForKey:uint256_obj(b.blockHash)];
            }
        }
    }*/

    // verify block difficulty
    if (![self verifyDifficultyFromPreviousBlockGLD:prev nextBlock:block]) {
        NSLog(@"%@:%d relayed block with invalid difficulty target at height %d, %x, blockHash: %@", peer.host, peer.port,
              block.height, block.target, blockHash);
        [self peerMisbehavin:peer];
        return;
    }

    [self.checkpoints[@(block.height)] getValue:&checkpoint];
    
    // verify block chain checkpoints
    if (! uint256_is_zero(checkpoint) && ! uint256_eq(block.blockHash, checkpoint)) {
        NSLog(@"%@:%d relayed a block that differs from the checkpoint at height %d, blockHash: %@, expected: %@",
              peer.host, peer.port, block.height, blockHash, self.checkpoints[@(block.height)]);
        [self peerMisbehavin:peer];
        return;
    }
    
    if (uint256_eq(block.prevBlock, self.lastBlock.blockHash)) { // new block extends main chain
        if ((block.height % 500) == 0 || txHashes.count > 0 || block.height > peer.lastblock) {
            NSLog(@"adding block at height: %d, false positive rate: %f", block.height, self.fpRate);
        }

        self.blocks[blockHash] = block;
        self.lastBlock = block;
        [self setBlockHeight:block.height andTimestamp:txTime - NSTimeIntervalSince1970 forTxHashes:txHashes];
        if (peer == self.downloadPeer) self.lastRelayTime = [NSDate timeIntervalSinceReferenceDate];
        self.downloadPeer.currentBlockHeight = block.height;
        if (block.height == _estimatedBlockHeight) syncDone = YES;
    }
    else if (self.blocks[blockHash] != nil) { // we already have the block (or at least the header)
        if ((block.height % 500) == 0 || txHashes.count > 0 || block.height > peer.lastblock) {
            NSLog(@"%@:%d relayed existing block at height %d", peer.host, peer.port, block.height);
        }

        self.blocks[blockHash] = block;

        BRMerkleBlock *b = self.lastBlock;

        while (b && b.height > block.height) b = self.blocks[uint256_obj(b.prevBlock)]; // is block in main chain?

        if (uint256_eq(b.blockHash, block.blockHash)) { // if it's not on a fork, set block heights for its transactions
            [self setBlockHeight:block.height andTimestamp:txTime - NSTimeIntervalSince1970 forTxHashes:txHashes];
            if (block.height == self.lastBlockHeight) self.lastBlock = block;
        }
    }
    else { // new block is on a fork
        if (block.height <= checkpoint_array[CHECKPOINT_COUNT - 1].height) { // fork is older than last checkpoint
            NSLog(@"ignoring block on fork older than most recent checkpoint, fork height: %d, blockHash: %@",
                  block.height, blockHash);
            return;
        }

        // special case, if a new block is mined while we're rescanning the chain, mark as orphan til we're caught up
        if (self.lastBlockHeight < peer.lastblock && block.height > self.lastBlockHeight + 1) {
            NSLog(@"marking new block at height %d as orphan until rescan completes", block.height);
            self.orphans[prevBlock] = block;
            self.lastOrphan = block;
            return;
        }

        NSLog(@"chain fork to height %d", block.height);
        self.blocks[blockHash] = block;
        if (block.height <= self.lastBlockHeight) return; // if fork is shorter than main chain, ignore it for now

        NSMutableArray *txHashes = [NSMutableArray array];
        BRMerkleBlock *b = block, *b2 = self.lastBlock;

        while (b && b2 && ! uint256_eq(b.blockHash, b2.blockHash)) { // walk back to where the fork joins the main chain
            b = self.blocks[uint256_obj(b.prevBlock)];
            if (b.height < b2.height) b2 = self.blocks[uint256_obj(b2.prevBlock)];
        }

        NSLog(@"reorganizing chain from height %d, new height is %d", b.height, block.height);

        // mark transactions after the join point as unconfirmed
        for (BRTransaction *tx in [BRWalletManager sharedInstance].wallet.allTransactions) {
            if (tx.blockHeight <= b.height) break;
            [txHashes addObject:uint256_obj(tx.txHash)];
        }

        [self setBlockHeight:TX_UNCONFIRMED andTimestamp:0 forTxHashes:txHashes];
        b = block;

        while (b.height > b2.height) { // set transaction heights for new main chain
            [self setBlockHeight:b.height andTimestamp:txTime - NSTimeIntervalSince1970 forTxHashes:b.txHashes];
            b = self.blocks[uint256_obj(b.prevBlock)];
            txTime = b.timestamp/2 + ((BRMerkleBlock *)self.blocks[uint256_obj(b.prevBlock)]).timestamp/2;
        }

        self.lastBlock = block;
        if (block.height == _estimatedBlockHeight) syncDone = YES;
    }

    if (syncDone) { // chain download is complete
        self.syncStartHeight = 0;
        [[NSUserDefaults standardUserDefaults] setInteger:0 forKey:SYNC_STARTHEIGHT_KEY];
        [self saveBlocks];
        [self loadMempools];
    }
    
    if (block.height > _estimatedBlockHeight) {
        _estimatedBlockHeight = block.height;
    
        // notify that transaction confirmations may have changed
        dispatch_async(dispatch_get_main_queue(), ^{
            [[NSNotificationCenter defaultCenter] postNotificationName:BRPeerManagerTxStatusNotification object:nil];
        });
    }
    
    // check if the next block was received as an orphan
    if (block == self.lastBlock && self.orphans[blockHash]) {
        BRMerkleBlock *b = self.orphans[blockHash];
        
        [self.orphans removeObjectForKey:blockHash];
        [self peer:peer relayedBlock:b];
    }
}

- (void)peer:(BRPeer *)peer notfoundTxHashes:(NSArray *)txHashes andBlockHashes:(NSArray *)blockhashes
{
    for (NSValue *hash in txHashes) {
        [self.txRelays[hash] removeObject:peer];
        [self.txRequests[hash] removeObject:peer];
    }
}

- (void)peer:(BRPeer *)peer setFeePerKb:(uint64_t)feePerKb
{
    BRWalletManager *manager = [BRWalletManager sharedInstance];
    uint64_t maxFeePerKb = 0, secondFeePerKb = 0;
    
    for (BRPeer *p in self.connectedPeers) { // find second highest fee rate
        if (p.status != BRPeerStatusConnected) continue;
        if (p.feePerKb > maxFeePerKb) secondFeePerKb = maxFeePerKb, maxFeePerKb = p.feePerKb;
    }
    
    if (secondFeePerKb*2 > MIN_FEE_PER_KB && secondFeePerKb*2 <= MAX_FEE_PER_KB &&
        secondFeePerKb*2 > manager.wallet.feePerKb) {
        NSLog(@"increasing feePerKb to %llu based on feefilter messages from peers", secondFeePerKb*2);
        manager.wallet.feePerKb = secondFeePerKb*2;
    }
}

- (BRTransaction *)peer:(BRPeer *)peer requestedTransaction:(UInt256)txHash
{
    BRWalletManager *manager = [BRWalletManager sharedInstance];
    NSValue *hash = uint256_obj(txHash);
    BRTransaction *tx = self.publishedTx[hash];
    void (^callback)(NSError *error) = self.publishedCallback[hash];
    NSError *error = nil;

    if (! self.txRelays[hash]) self.txRelays[hash] = [NSMutableSet set];
    [self.txRelays[hash] addObject:peer];
    [self.nonFpTx addObject:hash];
    [self.publishedCallback removeObjectForKey:hash];
    
    if (callback && ! [manager.wallet transactionIsValid:tx]) {
        [self.publishedTx removeObjectForKey:hash];
        error = [NSError errorWithDomain:@"BreadWallet" code:401
                 userInfo:@{NSLocalizedDescriptionKey:NSLocalizedString(@"double spend", nil)}];
    }
    else if (tx && ! [manager.wallet transactionForHash:txHash] && [manager.wallet registerTransaction:tx]) {
        [[BRTransactionEntity context] performBlock:^{
            [BRTransactionEntity saveContext]; // persist transactions to core data
        }];
    }
    
    dispatch_async(dispatch_get_main_queue(), ^{
        [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(txTimeout:) object:hash];
        if (callback) callback(error);
    });

//    [peer sendPingMessageWithPongHandler:^(BOOL success) { // check if peer will relay the transaction back
//        if (! success) return;
//        
//        if (! [self.txRequests[hash] containsObject:peer]) {
//            if (! self.txRequests[hash]) self.txRequests[hash] = [NSMutableSet set];
//            [self.txRequests[hash] addObject:peer];
//            [peer sendGetdataMessageWithTxHashes:@[hash] andBlockHashes:nil];
//        }
//    }];

    return tx;
}

// MARK: - UIAlertViewDelegate

- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex
{
    if (buttonIndex == alertView.cancelButtonIndex) return;
    [self rescan];
}


UInt256 setCompact(int32_t nCompact)
{
    int nSize = nCompact >> 24;
    UInt256 nWord = UINT256_ZERO;
    nWord.u32[0] = nCompact & 0x007fffff;
    if (nSize <= 3) {
        nWord = shiftRight(nWord, 8 * (3 - nSize));
    } else {
        nWord = shiftLeft(nWord, 8 * (nSize - 3));
    }
    return nWord;
}

uint8_t bits(UInt256 number)
{
    for (int pos = 8 - 1; pos >= 0; pos--) {
        if (number.u32[pos]) {
            for (int bits = 31; bits > 0; bits--) {
                if (number.u32[pos] & 1 << bits)
                    return 32 * pos + bits + 1;
            }
            return 32 * pos + 1;
        }
    }
    return 0;
}

int32_t getCompact(UInt256 number)
{
    int nSize = (bits(number) + 7) / 8;
    uint32_t nCompact = 0;
    if (nSize <= 3) {
        nCompact = number.u32[0] << 8 * (3 - nSize);
    } else {
        UInt256 bn = shiftRight(number, 8 * (nSize - 3));
        nCompact = bn.u32[0];
    }
    // The 0x00800000 bit denotes the sign.
    // Thus, if it is already set, divide the mantissa by 256 and increase the exponent.
    if (nCompact & 0x00800000) {
        nCompact >>= 8;
        nSize++;
    }
    assert((nCompact & ~0x007fffff) == 0);
    assert(nSize < 256);
    nCompact |= nSize << 24;
    return nCompact;
}

UInt256 add(UInt256 a, UInt256 b) {
    uint64_t carry = 0;
    UInt256 r = UINT256_ZERO;
    for (int i = 0; i < 8; i++) {
        uint64_t sum = (uint64_t)a.u32[i] + (uint64_t)b.u32[i] + carry;
        r.u32[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    return r;
}

UInt256 addOne(UInt256 a) {
    UInt256 r = ((UInt256) { .u64 = { 1, 0, 0, 0 } });
    return add(a, r);
}

UInt256 neg(UInt256 a) {
    UInt256 r = UINT256_ZERO;
    for (int i = 0; i < 4; i++) {
        r.u64[i] = ~a.u64[i];
    }
    return r;
}

UInt256 subtract(UInt256 a, UInt256 b) {
    return add(a,addOne(neg(b)));
}

UInt256 shiftLeft(UInt256 a, uint8_t bits) {
    UInt256 r = UINT256_ZERO;
    int k = bits / 64;
    bits = bits % 64;
    for (int i = 0; i < 4; i++) {
        if (i + k + 1 < 4 && bits != 0)
            r.u64[i + k + 1] |= (a.u64[i] >> (64 - bits));
        if (i + k < 4)
            r.u64[i + k] |= (a.u64[i] << bits);
    }
    return r;
}

UInt256 shiftRight(UInt256 a, uint8_t bits) {
    UInt256 r = UINT256_ZERO;
    int k = bits / 64;
    bits = bits % 64;
    for (int i = 0; i < 4; i++) {
        if (i - k - 1 >= 0 && bits != 0)
            r.u64[i - k - 1] |= (a.u64[i] << (64 - bits));
        if (i - k >= 0)
            r.u64[i - k] |= (a.u64[i] >> bits);
    }
    return r;
}

UInt256 divide (UInt256 a,UInt256 b)
{
    UInt256 div = b;     // make a copy, so we can shift.
    UInt256 num = a;     // make a copy, so we can subtract.
    UInt256 r = UINT256_ZERO;                  // the quotient.
    int num_bits = bits(num);
    int div_bits = bits(div);
    assert (div_bits != 0);
    if (div_bits > num_bits) // the result is certainly 0.
        return r;
    int shift = num_bits - div_bits;
    div = shiftLeft(div, shift); // shift so that div and nun align.
    while (shift >= 0) {
        if (uint256_supeq(num,div)) {
            num = subtract(num,div);
            r.u32[shift / 32] |= (1 << (shift & 31)); // set a bit of the result.
        }
        div = shiftRight(div, 1); // shift back.
        shift--;
    }
    // num now contains the remainder of the division.
    return r;
}

UInt256 multiplyThis32 (UInt256 a,uint32_t b)
{
    uint64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t n = carry + (uint64_t)b * (uint64_t)a.u32[i];
        a.u32[i] = n & 0xffffffff;
        carry = n >> 32;
    }
    return a;
}

#define MAX_PROOF_OF_WORK 0x1e0fffffu   // highest value for difficulty target (higher values are less difficult)
#define julyFork 45000
#define novemberFork  103000
#define novemberFork2  118800
#define mayFork 248000
#define febFork  372000
#define octoberFork  100000

#define julyFork2  251230

int compare_int64(const void *a,const void *b) {
    int64_t *x = (int64_t *) a;
    int64_t *y = (int64_t *) b;
    int64_t diff =  *x - *y;
    if(diff > 0)
        return 1;
    if(diff < 0)
        return -1;
    return 0;
}

- (BOOL)verifyDifficultyFromPreviousBlockGLD:(BRMerkleBlock *)pindexLast nextBlock:(BRMerkleBlock *)block
{
    //return next->_target == GetNextWorkRequired(previous, next, manager);
    
    static const int64_t nTargetTimespan = (2 * 60 * 60);// Difficulty changes every 60 blocks
    static const int64_t nTargetSpacing = 2.0 * 60;
    //Todo:: Clean this mess up.. -akumaburn
    unsigned int nProofOfWorkLimit = MAX_PROOF_OF_WORK;
    UInt256 bnNew = UINT256_ZERO;
    
    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit == block.target;
    
    // FeatherCoin difficulty adjustment protocol switch
    static const int nDifficultySwitchHeight = 21000;
    int nHeight = pindexLast.height + 1;
    bool fNewDifficultyProtocol = (nHeight >= nDifficultySwitchHeight);
    
    //julyFork2 whether or not we had a massive difficulty fall authorized
    bool didHalfAdjust = false;
    
    //msendheaoved to solve scope issues
    long long averageTime = 120;
    
    if (nHeight < julyFork) {
        //if(!hardForkedJuly) {
        int64_t nTargetTimespan2 = (7 * 24 * 60 * 60) / 8;
        int64_t nTargetSpacing2 = 2.5 * 60;
        
        int64_t nTargetTimespan2Current = fNewDifficultyProtocol ? nTargetTimespan2 : (nTargetTimespan2 * 4);
        int64_t nInterval = nTargetTimespan2Current / nTargetSpacing2;
        
        // Only change once per interval, or at protocol switch height
        if ((nHeight % nInterval != 0) &&
            (nHeight != nDifficultySwitchHeight))
        {
            // Special difficulty rule for testnet:
            /*if (fTestNet)
             {
             // If the new block's timestamp is more than 2* 10 minutes
             // then allow mining of a min-difficulty block.
             if (pblock->_timestamp > pindexLast->_timestamp + nTargetSpacing2 * 2)
             return nProofOfWorkLimit;
             else
             {
             // Return the last non-special-min-difficulty-rules-block
             const BRMerkleBlock* pindex = pindexLast;
             while (pindex->pprev && pindex->nHeight % nInterval != 0 && pindex->nBits == nProofOfWorkLimit)
             pindex = pindex->pprev;
             return pindex->nBits;
             }
             }*/
            
            return pindexLast.target == block.target;
        }
        
        // GoldCoin (GLD): This fixes an issue where a 51% attack can change difficulty at will.
        // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
        int64_t blockstogoback = nInterval - 1;
        if ((pindexLast.height + 1) != nInterval)
            blockstogoback = nInterval;
        BRMerkleBlock* pindexFirst = pindexLast;
        { // hit a difficulty transition, find previous transition time
            BRMerkleBlock *b = pindexLast;
            
            for (uint32_t i = 0; b && i < blockstogoback; i++) {
                b = self.blocks[uint256_obj(b.prevBlock)];
                if(b == nil)
                    return YES; //Let it go, not enough blocks
            }
            
            [[BRMerkleBlockEntity context] performBlock:^{ // save transition blocks to core data immediately
                @autoreleasepool {
                    BRMerkleBlockEntity *e = [BRMerkleBlockEntity objectsMatching:@"blockHash == %@",
                                              [NSData dataWithBytes:b.blockHash.u8 length:sizeof(UInt256)]].lastObject;
                    
                    if (! e) e = [BRMerkleBlockEntity managedObject];
                    [e setAttributesFromBlock:b];
                }
                
                [BRMerkleBlockEntity saveContext]; // persist core data to disk
            }];
            
            //transitionTime = b.timestamp;
            pindexFirst = b;
            
            while (b) { // free up some memory
                b = self.blocks[uint256_obj(b.prevBlock)];
                
                if (b && (b.height % nInterval) != 0) {
                    [self.blocks removeObjectForKey:uint256_obj(b.blockHash)];
                }
            }
        }
        
        // Limit adjustment step
        int64_t nActualTimespan = pindexLast.timestamp - pindexFirst.timestamp;
        //printf("  nActualTimespan = %"PRI64d"  before bounds\n", nActualTimespan);
        int64_t nActualTimespanMax = fNewDifficultyProtocol ? ((nTargetTimespan2Current * 99) / 70) : (nTargetTimespan2Current * 4);
        int64_t nActualTimespanMin = fNewDifficultyProtocol ? ((nTargetTimespan2Current * 70) / 99) : (nTargetTimespan2Current / 4);
        if (nActualTimespan < nActualTimespanMin)
            nActualTimespan = nActualTimespanMin;
        if (nActualTimespan > nActualTimespanMax)
            nActualTimespan = nActualTimespanMax;
        // Retarget
        bnNew = setCompact(pindexLast.target);
        bnNew = multiplyThis32(bnNew, (int32_t)nActualTimespan);
        bnNew = divide(bnNew, ((UInt256) { .u64 = { nTargetTimespan2Current, 0, 0, 0 } }));
        
        //if (bnNew > bnProofOfWorkLimit)
        //    bnNew = bnProofOfWorkLimit;
        
        /// debug print
        //printf("GetNextWorkRequired RETARGET\n");
        //printf("nTargetTimespan2 = %"PRI64d"    nActualTimespan = %"PRI64d"\n", nTargetTimespan2Current, nActualTimespan);
        //printf("Before: %08x  %s\n", pindexLast->nBits, CBigNum().SetCompact(pindexLast->nBits).getuint256().ToString().c_str());
        //printf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.getuint256().ToString().c_str());
        return getCompact(bnNew) == block.target;
    } else if (nHeight > novemberFork) {
        BOOL hardForkedNovember = true;
        
        int64_t nTargetTimespanCurrent = fNewDifficultyProtocol ? nTargetTimespan : (nTargetTimespan * 4);
        int64_t nInterval = nTargetTimespanCurrent / nTargetSpacing;
        
        // Only change once per interval, or at protocol switch height
        // After julyFork2 we change difficulty at every block.. so we want this only to happen before that..
        if ((nHeight % nInterval != 0) &&
            (nHeight != nDifficultySwitchHeight) && (nHeight <= julyFork2))
        {
            // Special difficulty rule for testnet:
            /*if (fTestNet)
            {
                // If the new block's timestamp is more than 2* 10 minutes
                // then allow mining of a min-difficulty block.
                if (pblock->nTime > pindexLast->nTime + nTargetSpacing * 2)
                    return nProofOfWorkLimit;
                else
                {
                    // Return the last non-special-min-difficulty-rules-block
                    const CBlockIndex* pindex = pindexLast;
                    while (pindex->pprev && pindex->nHeight % nInterval != 0 && pindex->nBits == nProofOfWorkLimit)
                        pindex = pindex->pprev;
                    return pindex->nBits;
                }
            }*/
            
            return pindexLast.target == block.target;
        }
        
        // GoldCoin (GLD): This fixes an issue where a 51% attack can change difficulty at will.
        // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
        BRMerkleBlock* pindexFirst = pindexLast;
        { // hit a difficulty transition, find previous transition time
                    }
        
        BRMerkleBlock * tblock1 = pindexLast;//We want to copy pindexLast to avoid changing it accidentally
        BRMerkleBlock * tblock2 = tblock1;
        
        //std::vector<int64_t> last60BlockTimes;
        int64_t last60BlockTimes[60];
        int count = 0;
        // Limit adjustment step
        //We need to set this in a way that reflects how fast blocks are actually being solved..
        //First we find the last 60 blocks and take the time between blocks
        //That gives us a list of 59 time differences
        //Then we take the median of those times and multiply it by 60 to get our actualtimespan
        while (count < 60) {
            last60BlockTimes[count] = tblock2.timestamp;
            //if (tblock2->pprev) //should always be so
            //    tblock2 = tblock2->pprev;
         
            //[last60BlockTimes addObject:tblock2.timestamp]
            //for (uint32_t i = 0; b && i < nInterval; i++) {
                tblock2 = self.blocks[uint256_obj(tblock2.prevBlock)];
                if(tblock2 == nil)
                    return YES; // Let it go, we don't have enough blocks.
            //}
            count++;
        }
        //std::vector<int64_t> last59TimeDifferences;
        int64_t last59TimeDifferences[59];
        int xy = 0;
        while (xy < 59) {
            last59TimeDifferences[xy] = (llabs(last60BlockTimes[xy] - last60BlockTimes[xy + 1]));
            xy++;
        }
        
        qsort(last59TimeDifferences, 59, sizeof(int64_t), compare_int64);
        
        //printf("  Median Time between blocks is: %" PRI64d" \n", last59TimeDifferences[29]);
        int64_t nActualTimespan = llabs((last59TimeDifferences[29]));
        int64_t medTime = nActualTimespan;
        
        if (nHeight > mayFork) {
            
            
            //Difficulty Fix here for case where average time between blocks becomes far longer than 2 minutes, even though median time is close to 2 minutes.
            //Uses the last 120 blocks(Should be 4 hours) for calculating
            
            //printf(" GetNextWorkRequired(): May Fork mode \n");
            
            BRMerkleBlock * tblock1 = pindexLast;//We want to copy pindexLast to avoid changing it accidentally
            BRMerkleBlock* tblock2 = tblock1;
            /*
            std::vector<int64_t> last120BlockTimes;
            // Limit adjustment step
            //We need to set this in a way that reflects how fast blocks are actually being solved..
            //First we find the last 120 blocks and take the time between blocks
            //That gives us a list of 119 time differences
            //Then we take the average of those times and multiply it by 60 to get our actualtimespan
            while (last120BlockTimes.size() < 120) {
                last120BlockTimes.push_back(tblock2->GetBlockTime());
                if (tblock2->pprev) //should always be so
                    tblock2 = tblock2->pprev;
            }
            std::vector<int64_t> last119TimeDifferences;
            
            int xy = 0;
            while (last119TimeDifferences.size() != 119) {
                if (xy == 119) {
                    printf(" GetNextWorkRequired(): This shouldn't have happened 2 \n");
                    break;
                }
                last119TimeDifferences.push_back(llabs(last120BlockTimes[xy] - last120BlockTimes[xy + 1]));
                xy++;
            }
            */
            int64_t last120BlockTimes[120];
            int count = 0;
            // Limit adjustment step
            //We need to set this in a way that reflects how fast blocks are actually being solved..
            //First we find the last 60 blocks and take the time between blocks
            //That gives us a list of 59 time differences
            //Then we take the median of those times and multiply it by 60 to get our actualtimespan
            while (count < 120) {
                
                //if (tblock2->pprev) //should always be so
                //    tblock2 = tblock2->pprev;
                //BRMerkleBlock *b = tblock2;
                //[last60BlockTimes addObject:tblock2.timestamp]
                last120BlockTimes[count] = tblock2.timestamp;
                //for (uint32_t i = 0; tblock2 && i < nInterval; i++) {
                    tblock2 = self.blocks[uint256_obj(tblock2.prevBlock)];
                if(tblock2 == nil)
                    return YES; // Let it go, we don't have enough blocks.
             //   }
                count++;
            }
            //std::vector<int64_t> last59TimeDifferences;
            int64_t last119TimeDifferences[119];
            int xy = 0;
            while (xy < 119) {
                last119TimeDifferences[xy] = (llabs(last120BlockTimes[xy] - last120BlockTimes[xy + 1]));
                xy++;
            }
            
            //qsort(last119TimeDifferences, 119, sizeof(int64_t), compare_int64);
            int64_t total = 0;
            
            for (int x = 0; x < 119; x++) {
                int64_t timeN = last119TimeDifferences[x];
                //printf(" GetNextWorkRequired(): Current Time difference is: %"PRI64d" \n",timeN);
                total += timeN;
            }
            
            averageTime = total / 119;
            
            
            //printf(" GetNextWorkRequired(): Average time between blocks over the last 120 blocks is: %"PRI64d" \n", averageTime);
            /*printf(" GetNextWorkRequired(): Total Time (over 119 time differences) is: %"PRI64d" \n",total);
             printf(" GetNextWorkRequired(): First Time (over 119 time differences) is: %"PRI64d" \n",last119TimeDifferences[0]);
             printf(" GetNextWorkRequired(): Last Time (over 119 time differences) is: %"PRI64d" \n",last119TimeDifferences[118]);
             printf(" GetNextWorkRequired(): Last Time is: %"PRI64d" \n",last120BlockTimes[119]);
             printf(" GetNextWorkRequired(): 2nd Last Time is: %"PRI64d" \n",last120BlockTimes[118]);
             printf(" GetNextWorkRequired(): First Time is: %"PRI64d" \n",last120BlockTimes[0]);
             printf(" GetNextWorkRequired(): 2nd Time is: %"PRI64d" \n",last120BlockTimes[1]);*/
            
            if (nHeight <= julyFork2) {
                //If the average time between blocks exceeds or is equal to 3 minutes then increase the med time accordingly
                if (averageTime >= 180) {
                    printf(" \n Average Time between blocks is too high.. Attempting to Adjust.. \n ");
                    medTime = 130;
                } else if (averageTime >= 108 && medTime < 120) {
                    //If the average time between blocks is more than 1.8 minutes and medTime is less than 120 seconds (which would ordinarily prompt an increase in difficulty)
                    //limit the stepping to something reasonable(so we don't see massive difficulty spike followed by miners leaving in these situations).
                    medTime = 110;
                    printf(" \n Medium Time between blocks is too low compared to average time.. Attempting to Adjust.. \n ");
                }
            } else {//julyFork2 changes here
                
                //Calculate difficulty of previous block as a double
                /*int nShift = (pindexLast->nBits >> 24) & 0xff;
                 double dDiff =
                 (double)0x0000ffff / (double)(pindexLast->nBits & 0x00ffffff);
                 while (nShift < 29)
                 {
                 dDiff *= 256.0;
                 nShift++;
                 }
                 while (nShift > 29)
                 {
                 dDiff /= 256.0;
                 nShift--;
                 } */
                
                //int64_t hashrate = (int64_t)(dDiff * pow(2.0,32.0))/((medTime > averageTime)?averageTime:medTime);
                
                medTime = (medTime > averageTime) ? averageTime : medTime;
                
                if (averageTime >= 180 && last119TimeDifferences[0] >= 1200 && last119TimeDifferences[1] >= 1200) {
                    didHalfAdjust = true;
                    medTime = 240;
                }
                
            }
        }
        
        //Fixes an issue where median time between blocks is greater than 120 seconds and is not permitted to be lower by the defence system
        //Causing difficulty to drop without end
        
        if (nHeight > novemberFork2) {
            if (medTime >= 120) {
                //Check to see whether we are in a deadlock situation with the 51% defense system
                //printf("  Checking for DeadLocks \n");
                int numTooClose = 0;
                int index = 1;
                while (index != 55) {
                    if (llabs(last60BlockTimes[60 - index] - last60BlockTimes[60 - (index + 5)]) == 600) {
                        numTooClose++;
                    }
                    index++;
                }
                
                if (numTooClose > 0) {
                    //We found 6 blocks that were solved in exactly 10 minutes
                    //Averaging 1.66 minutes per block
                    //printf(" \n DeadLock detected and fixed - Difficulty Increased to avoid bleeding edge of defence system \n");
                    
                    if (nHeight > julyFork2) {
                        medTime = 119;
                    } else {
                        medTime = 110;
                    }
                } else {
                    //printf(" \n DeadLock not detected. \n");
                }
                
                
            }
        }
        
        
        if (nHeight > julyFork2) {
            //216 == (int64_t) 180.0/100.0 * 120
            //122 == (int64_t) 102.0/100.0 * 120 == 122.4
            if (averageTime > 216 || medTime > 122) {
                if (didHalfAdjust) {
                    // If the average time between blocks was
                    // too high.. allow a dramatic difficulty
                    // fall..
                    medTime = (int64_t)(120 * 142.0 / 100.0);
                } else {
                    // Otherwise only allow a 120/119 fall per block
                    // maximum.. As we now adjust per block..
                    // 121 == (int64_t) 120 * 120.0/119.0
                    medTime = 121;
                }
            }
            // 117 -- (int64_t) 120.0 * 98.0/100.0
            else if (averageTime < 117 || medTime < 117)  {
                // If the average time between blocks is within 2% of target
                // value
                // Or if the median time stamp between blocks is within 2% of
                // the target value
                // Limit diff increase to 2%
                medTime = 117;
            }
            nActualTimespan = medTime * 60;
        } else {
            
            nActualTimespan = medTime * 60;
            
            //printf("  nActualTimespan = %"PRI64d"  before bounds\n", nActualTimespan);
            int64_t nActualTimespanMax = fNewDifficultyProtocol ? ((nTargetTimespanCurrent * 99) / 70) : (nTargetTimespanCurrent * 4);
            int64_t nActualTimespanMin = fNewDifficultyProtocol ? ((nTargetTimespanCurrent * 70) / 99) : (nTargetTimespanCurrent / 4);
            if (nActualTimespan < nActualTimespanMin)
                nActualTimespan = nActualTimespanMin;
            if (nActualTimespan > nActualTimespanMax)
                nActualTimespan = nActualTimespanMax;
            
        }
        
        
        if (nHeight > julyFork2) {
            BRMerkleBlock * tblock11 = pindexLast;//We want to copy pindexLast to avoid changing it accidentally
            BRMerkleBlock * tblock22 = tblock11;
            
            // We want to limit the possible difficulty raise/fall over 60 and 240 blocks here
            // So we get the difficulty at 60 and 240 blocks ago
            
            int64_t nbits60ago = 0;
            int64_t nbits240ago = 0;
            int counter = 0;
            //Note: 0 is the current block, we want 60 past current
            while (counter <= 240) {
                if (counter == 60) {
                    nbits60ago = tblock22.target;
                } else if (counter == 240) {
                    nbits240ago = tblock22.target;
                }
                //if (tblock22->pprev) //should always be so
                //    tblock22 = tblock22->pprev;
                
                tblock22 = self.blocks[uint256_obj(tblock22.prevBlock)];
                if(!tblock22)
                    return YES;
                counter++;
            }
            
            while (tblock22) { // free up some memory
                tblock22 = self.blocks[uint256_obj(tblock22.prevBlock)];
                
                if (tblock22 && (tblock22.height % 240) != 0) {
                    [self.blocks removeObjectForKey:uint256_obj(tblock22.blockHash)];
                }
            }
            
            //Now we get the old targets
            UInt256 bn60ago = UINT256_ZERO, bn240ago = UINT256_ZERO, bnLast = UINT256_ZERO;
            bn60ago = setCompact(nbits60ago);
            bn240ago = setCompact(nbits240ago);
            bnLast = setCompact(pindexLast.target);
            
            //Set the new target
            bnNew = setCompact(pindexLast.target);
            bnNew = multiplyThis32(bnNew, nActualTimespan);
            bnNew = divide(bnNew, ((UInt256) { .u64 = { nTargetTimespanCurrent, 0, 0, 0 } }));
            
            
            //Now we have the difficulty at those blocks..
            
            // Set a floor on difficulty decreases per block(20% lower maximum
            // than the previous block difficulty).. when there was no halfing
            // necessary.. 10/8 == 1.0/0.8
            bnLast = multiplyThis32(bnLast, 10);
            bnLast = divide(bnLast, ((UInt256) { .u64 = { 8, 0, 0, 0 } }));;
            
            if (!didHalfAdjust && uint256_sup(bnNew, bnLast)) {
                bnNew = setCompact(getCompact(bnLast));
            }
            
            bnLast = multiplyThis32(bnLast, 8);
            bnLast = divide(bnLast, ((UInt256) { .u64 = { 10, 0, 0, 0 } }));;
            
            // Set ceilings on difficulty increases per block
            
            //1.0/1.02 == 100/102
            bn60ago = multiplyThis32(bn60ago, 100);
            bn60ago = divide(bn60ago, ((UInt256) { .u64 = { 102, 0, 0, 0 } }));
            
            if (uint256_sup(bn60ago, bnNew)) {
                bnNew = setCompact(getCompact(bn60ago));
            }
            
            bn60ago = multiplyThis32(bn60ago,102);
            bn60ago = divide(bn60ago, ((UInt256) { .u64 = { 100, 0, 0, 0 } }));
            
            //1.0/(1.02*4) ==  100 / 408
            
            bn240ago = multiplyThis32(bn240ago,100);
            bn240ago = divide(bn240ago, ((UInt256) { .u64 = { 408, 0, 0, 0 } }));
            
            if (uint256_sup(bn240ago, bnNew)) {
                bnNew = setCompact(getCompact(bn240ago));;
            }
            
            bn240ago = multiplyThis32(bn240ago, 408);
            bn240ago = divide(bn240ago, ((UInt256) { .u64 = { 100, 0, 0, 0 } }));
            
            
        } else {
            // Retarget
            bnNew = setCompact(pindexLast.target);
            bnNew = multiplyThis32(bnNew, nActualTimespan);
            bnNew = divide(bnNew, ((UInt256) { .u64 = { nTargetTimespanCurrent, 0, 0, 0 } }));
        }
        
        //Sets a ceiling on highest target value (lowest possible difficulty)
        if (getCompact(bnNew) > nProofOfWorkLimit)
            bnNew = setCompact(nProofOfWorkLimit);
        
        /// debug print
        //printf("GetNextWorkRequired RETARGET\n");
        //printf("nTargetTimespan = %d    nActualTimespan = %d\n", (int)nTargetTimespanCurrent, (int)nActualTimespan);
        //printf("Before: %08x  \n", pindexLast.target);
        //printf("After:  %08x  \n", getCompact(bnNew));
    } else {
        int hardForkedJuly = true;
        int64_t nTargetTimespanCurrent = fNewDifficultyProtocol ? nTargetTimespan : (nTargetTimespan * 4);
        int64_t nInterval = nTargetTimespanCurrent / nTargetSpacing;
#if BITCOIN_TESTNET
        int fTestnet = TRUE;
#else
        int fTestNet = FALSE;
#endif
        // Only change once per interval, or at protocol switch height
        if ((nHeight % nInterval != 0) &&
            (nHeight != nDifficultySwitchHeight || fTestNet))
        {
#if BITCOIN_TESTNET
            // Special difficulty rule for testnet:
            {
                // If the new block's timestamp is more than 2* 10 minutes
                // then allow mining of a min-difficulty block.
                if (pblock->nTime > pindexLast->nTime + nTargetSpacing * 2)
                    return nProofOfWorkLimit == block.target;
                else
                {
                    // Return the last non-special-min-difficulty-rules-block
                    const BRMerkleBlock* pindex = pindexLast;
                    while (pindex.height % nInterval != 0 && pindex.target == nProofOfWorkLimit)
                        pindex = self.blocks[uint256_obj(pindex.prevBlock);
                    

                    return pindex.target == block.target;
                    
                }
            }
#endif
            
            return pindexLast.target == block.target;
        }
        
        // GoldCoin (GLD): This fixes an issue where a 51% attack can change difficulty at will.
        // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
        int blockstogoback = nInterval - 1;
        if ((pindexLast.height + 1) != nInterval)
            blockstogoback = nInterval;
        const BRMerkleBlock* pindexFirst = pindexLast;
        for (int i = 0; pindexFirst && i < blockstogoback; i++)
        {
            pindexFirst = self.blocks[uint256_obj(pindexFirst.prevBlock)];
            if(!pindexFirst)
                return YES;
        
        }
        assert(pindexFirst);
        
        // Limit adjustment step
        int64_t nActualTimespan = pindexLast.timestamp - pindexFirst.timestamp;
        //printf("  nActualTimespan = %"PRI64d"  before bounds\n", nActualTimespan);
        int64_t nActualTimespanMax = fNewDifficultyProtocol ? ((nTargetTimespanCurrent * 99) / 70) : (nTargetTimespanCurrent * 4);
        int64_t nActualTimespanMin = fNewDifficultyProtocol ? ((nTargetTimespanCurrent * 70) / 99) : (nTargetTimespanCurrent / 4);
        if (nActualTimespan < nActualTimespanMin)
            nActualTimespan = nActualTimespanMin;
        if (nActualTimespan > nActualTimespanMax)
            nActualTimespan = nActualTimespanMax;
        // Retarget
        bnNew = setCompact(pindexLast.target);
        bnNew = multiplyThis32(bnNew,nActualTimespan);
        bnNew = divide(bnNew, ((UInt256) { .u64 = { nTargetTimespanCurrent, 0, 0, 0 } }));
        
        if (uint256_sup(bnNew, setCompact(nProofOfWorkLimit)))
            bnNew = setCompact(nProofOfWorkLimit);
        
        /// debug print
        //printf("GetNextWorkRequired RETARGET\n");
        //printf("nTargetTimespan = %"PRI64d"    nActualTimespan = %"PRI64d"\n", nTargetTimespanCurrent, nActualTimespan);
        //printf("Before: %08x  %s\n", pindexLast->nBits, CBigNum().SetCompact(pindexLast->nBits).getuint256().ToString().c_str());
        //printf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.getuint256().ToString().c_str());
    }
    return getCompact(bnNew) == block.target;
}

@end
