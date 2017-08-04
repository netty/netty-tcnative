package io.netty.gradle.plugins.dockerbuild;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Supplier;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.plugins.BasePlugin;

import com.bmuschko.gradle.docker.DockerRemoteApiPlugin;
import com.bmuschko.gradle.docker.tasks.container.DockerCreateContainer;
import com.bmuschko.gradle.docker.tasks.container.DockerRemoveContainer;
import com.bmuschko.gradle.docker.tasks.container.DockerStartContainer;
import com.bmuschko.gradle.docker.tasks.container.DockerWaitContainer;
import com.bmuschko.gradle.docker.tasks.image.DockerBuildImage;
import com.bmuschko.gradle.docker.tasks.image.Dockerfile;

import groovy.lang.Closure;

public class DockerBuildPlugin implements Plugin<Project> {

    private Project project;
    private DockerBuildExtension config;

    @Override
    public void apply(Project project) {
        this.project = project;
        this.config = project.getExtensions().create("dockerBuild", DockerBuildExtension.class);

        project.getRepositories().jcenter();

        project.getPluginManager().apply(BasePlugin.class);
        project.getPluginManager().apply(DockerRemoteApiPlugin.class);

        project.afterEvaluate((unused) -> addTasks());
    }

    private void addTasks() {
        Dockerfile dockerFileTask = project.getTasks().create("dockerFile", Dockerfile.class);
        dockerFileTask.setDestFile(new File(project.getBuildDir(), "docker-image/Dockerfile"));
        dockerFileTask.from(config.getBaseImage());
        dockerFileTask.maintainer("Netty Team (https://github.com/netty");
        config.getRunCommands().forEach(dockerFileTask::runCommand);
        dockerFileTask.addFile(".", "/netty-tcnative");
        dockerFileTask.volume("/root/.m2");
        dockerFileTask.volume("/output");
        dockerFileTask.workingDir("/netty-tcnative");
        dockerFileTask.defaultCommand("sh", "-c", config.getScript());

        DockerBuildImage buildImageTask = project.getTasks().create("buildImage", DockerBuildImage.class);
        buildImageTask.dependsOn(dockerFileTask);
        buildImageTask.setInputDir(project.getRootProject().getProjectDir());
        buildImageTask.setDockerFile(dockerFileTask.getDestFile());
        buildImageTask.setTag("netty-tcnative-" + project.getName() + "-builder:latest");

        DockerCreateContainer createContainerTask = project.getTasks().create(
                "createContainer", DockerCreateContainer.class);
        createContainerTask.dependsOn(buildImageTask);
        createContainerTask.targetImageId(noArgClosure(buildImageTask::getImageId));
        Map<String, String> binds = new HashMap<>();
        binds.put(new File(project.getBuildDir(), "libs").getAbsolutePath(), "/output");
        binds.put(new File(System.getProperty("user.home") + "/.m2").getAbsolutePath(), "/root/.m2");
        createContainerTask.setBinds(binds);
        createContainerTask.doFirst(t -> {
            project.mkdir(new File(project.getBuildDir(), "libs/boringssl-static"));
            project.mkdir(new File(project.getBuildDir(), "libs/libressl-static"));
            project.mkdir(new File(project.getBuildDir(), "libs/openssl-dynamic"));
            project.mkdir(new File(project.getBuildDir(), "libs/openssl-static"));
        });

        DockerStartContainer startContainerTask = project.getTasks().create(
                "startContainer", DockerStartContainer.class);
        startContainerTask.dependsOn(createContainerTask);
        startContainerTask.targetContainerId(noArgClosure(createContainerTask::getContainerId));

        DockerRemoveContainer removeContainerTask = project.getTasks().create(
                "removeContainer", DockerRemoveContainer.class);
        removeContainerTask.dependsOn(createContainerTask);
        removeContainerTask.targetContainerId(noArgClosure(createContainerTask::getContainerId));
        removeContainerTask.setForce(true);
        removeContainerTask.setOnError(oneArgClosure((exception) -> {
            Exception ex = (Exception) exception;
            // Ignore missing container which happens on successful build
            if (!(ex.getMessage().contains("No such container"))) {
                throw new RuntimeException(ex);
            }
        }));

        DockerWaitContainer waitContainerTask = project.getTasks().create(
                "waitContainer", DockerWaitContainer.class);
        waitContainerTask.dependsOn(startContainerTask);
        waitContainerTask.finalizedBy(removeContainerTask);
        waitContainerTask.targetContainerId(noArgClosure(() -> {
            String containerId = createContainerTask.getContainerId();
            System.out.println("Logs for " + project.getName() + " available with: "
                               + "'docker logs -f " + containerId + "'");
            return containerId;
        }).memoize());

        project.getTasks().getByName("build").dependsOn(waitContainerTask);
    }

    private Closure noArgClosure(Supplier<Object> result) {
        return new Closure(this) {
            protected Object doCall(Object unused) {
                return result.get();
            }
        };
    }

    private Closure oneArgClosure(Consumer<Object> consumer) {
        return new Closure(this) {
            protected Object doCall(Object arg) {
                consumer.accept(arg);
                return null;
            }
        };
    }
}
