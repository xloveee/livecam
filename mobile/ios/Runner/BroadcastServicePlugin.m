#import <Flutter/Flutter.h>

@interface BroadcastServicePlugin : NSObject<FlutterPlugin>
@end

@implementation BroadcastServicePlugin

+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  FlutterMethodChannel* channel = [FlutterMethodChannel
      methodChannelWithName:@"com.livecam.mobile/broadcast_service"
            binaryMessenger:[registrar messenger]];
  BroadcastServicePlugin* instance = [[BroadcastServicePlugin alloc] init];
  [registrar addMethodCallDelegate:instance channel:channel];
}

- (void)handleMethodCall:(FlutterMethodCall*)call result:(FlutterResult)result {
  if ([@"start" isEqualToString:call.method] || [@"stop" isEqualToString:call.method]) {
    result(nil);
  } else {
    result(FlutterMethodNotImplemented);
  }
}

@end
